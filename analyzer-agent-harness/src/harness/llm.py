"""LLM client (LiteLLM) and the per-finding review step."""

import ast
import asyncio
import json
import logging
import re
from pathlib import Path

from harness.scanners.findings import mask_lines, read_lines

log = logging.getLogger(__name__)

VERDICTS = ("likely_real", "likely_false_positive", "unsure")
REVIEW_CONTEXT_LINES = 20  # lines on each side, about 40 in total
CHARS_PER_TOKEN = 4
RESERVED_TOKENS = 2000  # instructions plus the reply


class LLMError(Exception):
    pass


class LLMUnreachable(LLMError):
    pass


class LLM:
    """`complete(messages, tools=None)` returns {"content": str|None, "tool_calls": [...]}.
    Tool calls are {"id", "name", "arguments" (str)}. Tests pass a fake `completion`."""

    def __init__(self, cfg, completion=None):
        self.cfg = cfg
        self._completion = completion or self._litellm

    async def _litellm(self, messages, tools=None):
        import litellm
        kwargs = dict(model=self.cfg.llm_model, messages=messages, api_base=self.cfg.llm_base_url,
                      api_key=self.cfg.llm_api_key, timeout=self.cfg.llm_timeout_seconds)
        if tools:
            kwargs["tools"] = tools
        network_errors = (litellm.APIConnectionError, litellm.Timeout,
                          litellm.ServiceUnavailableError, litellm.InternalServerError)
        for attempt in (1, 2):
            try:
                resp = await litellm.acompletion(**kwargs)
                break
            except network_errors as e:
                if attempt == 2:
                    raise LLMUnreachable(f"The LLM cannot be reached at {self.cfg.llm_base_url}") from e
                log.warning("LLM call failed (%s), retrying once", type(e).__name__)
                await asyncio.sleep(1)
            except Exception as e:  # any other LiteLLM/OpenAI error (400s, bad output from the server)
                log.warning("LLM call failed: %s", type(e).__name__)
                raise LLMError(f"The LLM returned an error ({_short(e)})") from e
        msg = resp.choices[0].message
        calls = [{"id": c.id, "name": c.function.name, "arguments": c.function.arguments or "{}"}
                 for c in (getattr(msg, "tool_calls", None) or [])]
        return {"content": msg.content, "tool_calls": calls}

    async def complete(self, messages, tools=None):
        return await self._completion(messages, tools)

    @property
    def max_code_chars(self):
        return max((self.cfg.llm_context_tokens - RESERVED_TOKENS) * CHARS_PER_TOKEN, 2000)


def _short(e):
    """A short, single-line reason from an LLM error, without request details."""
    text = str(e).replace("\n", " ")
    for marker in ('"message":"', "'message': '", "message="):
        if marker in text:
            text = text.split(marker, 1)[1]
            break
    return text.split('"', 1)[0].split("'", 1)[0].strip()[:160] or type(e).__name__


REVIEW_SYSTEM = """You review findings from security scanners. Decide if each one is a real problem.
Reply with one JSON object only, no other text:
{"verdict": "likely_real" | "likely_false_positive" | "unsure",
 "explanation": "plain-language explanation of the problem and why it matters, or why it is a false alarm",
 "fix_recommendation": "plain-language steps to fix it",
 "suggested_patch": "replacement code for the affected lines, or null"}
Write for a developer who is not a security expert. Keep it short."""

REMINDER = "Your last reply was not valid JSON with the required fields. Reply with only the JSON object."


def code_context(code_dir, finding, max_chars):
    """About 40 lines around the finding, with line numbers and secrets masked, cut to fit."""
    lines = read_lines(Path(code_dir) / finding["path"])
    start, end = finding["start_line"], finding["end_line"]
    before = after = REVIEW_CONTEXT_LINES
    while True:
        first = max(start - before, 1)
        last = min(end + after, len(lines))
        chunk = mask_lines(lines[first - 1:last], first, finding.get("_mask", []))
        text = "\n".join(f"{first + i:>5} | {l}" for i, l in enumerate(chunk))
        if len(text) <= max_chars or (before == 0 and after == 0):
            return text[:max_chars]
        before, after = before // 2, after // 2


def _loads_lenient(text):
    """JSON, or the near-JSON small models often write (single-quoted strings, Python literals)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return ast.literal_eval(re.sub(r"\b(null|true|false)\b",
                                       lambda m: {"null": "None", "true": "True", "false": "False"}[m.group(1)], text))
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None


def _patch_text(patch):
    """The patch as text. Models sometimes send {"original...": ..., "replacement...": ...},
    a list of lines, or (read leniently) a set of lines."""
    if isinstance(patch, dict):
        parts = [_patch_text(v) for k, v in patch.items() if "replac" in str(k).lower() or "new" in str(k).lower()]
        patch = "\n".join(p for p in parts if p) if any(parts) else json.dumps(patch, indent=2, default=str)
    elif isinstance(patch, (list, tuple, set)):
        patch = "\n".join(str(p) for p in patch)
    elif patch is not None and not isinstance(patch, str):
        patch = str(patch)
    return patch if isinstance(patch, str) and patch.strip() else None


def parse_review(text):
    """Return a valid review dict from the model's text, or None. Never raises:
    a reply we cannot read is treated like invalid JSON."""
    try:
        return _parse_review(text)
    except Exception:
        log.warning("could not read an LLM review reply")
        return None


def _parse_review(text):
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.DOTALL)
    data = _loads_lenient(m.group(0)) if m else None
    if not isinstance(data, dict):
        return None
    verdict = str(data.get("verdict", "")).strip().lower().replace(" ", "_").replace("-", "_")
    if verdict not in VERDICTS:
        return None
    if not isinstance(data.get("explanation"), str) or not isinstance(data.get("fix_recommendation"), str):
        return None
    return {"verdict": verdict, "explanation": data["explanation"].strip(),
            "fix_recommendation": data["fix_recommendation"].strip(),
            "suggested_patch": _patch_text(data.get("suggested_patch"))}


FAILED_REVIEW = {"verdict": "unsure", "explanation": "The automatic review failed, so this finding was not checked.",
                 "fix_recommendation": "Review this finding by hand.", "suggested_patch": None}


async def review_one(llm, finding, code_dir):
    prompt = (f"Tool(s): {', '.join(finding['tools'])}\nRule: {finding['rule_id']}\n"
              f"Title: {finding['title']}\nSeverity: {finding['severity']}\nCWE: {finding['cwe'] or 'unknown'}\n"
              f"Tool message: {finding['message']}\nFile: {finding['path']} "
              f"(lines {finding['start_line']}-{finding['end_line']})\n\nCode:\n"
              + code_context(code_dir, finding, llm.max_code_chars))
    messages = [{"role": "system", "content": REVIEW_SYSTEM}, {"role": "user", "content": prompt}]
    reply = await llm.complete(messages)
    review = parse_review(reply.get("content"))
    if review is None:
        messages += [{"role": "assistant", "content": reply.get("content") or ""},
                     {"role": "user", "content": REMINDER}]
        review = parse_review((await llm.complete(messages)).get("content"))
    return review


async def review_findings(findings, code_dir, llm, db, max_parallel, on_progress=None):
    """Fill the LLM fields of every finding. Cached reviews (same id and file hash)
    are reused without calling the LLM. `on_progress(done, total, finding)` is awaited after each review.
    Returns (reviews attempted, error message or None)."""
    todo = []
    for f in findings:
        cached = db.get_review(f["id"], f["file_sha256"])
        if cached:
            f.update(cached)
        else:
            todo.append(f)
    sem = asyncio.Semaphore(max_parallel)
    done = 0
    unreachable = None

    async def one(f):
        nonlocal done, unreachable
        async with sem:
            review = None
            if not unreachable:  # once the LLM is down, don't wait out a timeout per finding
                try:
                    review = await review_one(llm, f, code_dir)
                except LLMUnreachable as e:
                    unreachable = str(e)
                    log.warning("%s; skipping the remaining reviews", e)
                except LLMError as e:
                    log.warning("review of a finding failed: %s", e)
                except Exception:  # one bad review must never fail the whole scan
                    log.exception("review of a finding failed unexpectedly")
        f.update(review or FAILED_REVIEW)
        if review:  # only cache real reviews, so a failed one is retried next scan
            db.put_review(f["id"], f["file_sha256"], review)
        done += 1
        if on_progress:
            await on_progress(done, len(todo), f)

    await asyncio.gather(*(one(f) for f in todo))
    return len(todo), unreachable
