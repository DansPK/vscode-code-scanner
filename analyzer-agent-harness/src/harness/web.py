"""Web tools for the LLM agents: search (through a SearXNG instance) and reading a page.

Both send data out of the harness, so:
- search queries are short and may not contain a masked secret (`****`);
- pages are fetched only from public addresses: never the LAN, the Docker network, localhost or
  cloud metadata, checked again on every redirect.
"""

import asyncio
import ipaddress
import re
import socket
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

MAX_QUERY_CHARS = 200
MAX_RESULTS = 8
MAX_PAGE_BYTES = 2_000_000
MAX_PAGE_CHARS = 8000
MAX_REDIRECTS = 3
TIMEOUT_SECONDS = 15
USER_AGENT = "vuln-scanner-harness/0.1 (security fix assistant)"

PROMPT = """You can also search the web (web_search) and read a page (fetch_url), for example for a CVE,
a library's safe API, or current advice for a rule. Search queries leave this machine: never put code,
secrets, file paths, or names of this project in them; ask about the general problem instead."""

TOOLS = [
    {"type": "function", "function": {
        "name": "web_search", "description": "Search the web. Returns titles, links and short snippets.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "General question; no code, secrets or project names"}},
            "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "fetch_url", "description": "Read the text of a public web page (for example a search result).",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
]
NAMES = {t["function"]["name"] for t in TOOLS}


class WebError(Exception):
    """The message goes back to the model."""


def check_query(query):
    q = " ".join(str(query or "").split())
    if not q:
        raise WebError("the query is empty")
    if "****" in q:
        raise WebError("the query contains a hidden secret; search for the general problem instead")
    return q[:MAX_QUERY_CHARS]


async def search(base_url, query, limit=5):
    """Results from SearXNG's JSON API: [{"title", "url", "snippet"}]."""
    q = check_query(query)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, headers={"User-Agent": USER_AGENT}) as client:
            r = await client.get(base_url.rstrip("/") + "/search", params={"q": q, "format": "json"})
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise WebError(f"web search failed ({type(e).__name__})") from None
    out = []
    for item in data.get("results", [])[:max(1, min(int(limit or 5), MAX_RESULTS))]:
        out.append({"title": str(item.get("title", ""))[:200], "url": str(item.get("url", "")),
                    "snippet": " ".join(str(item.get("content", "")).split())[:300]})
    return out


def _public(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global


async def check_url(url):
    """Raise WebError unless `url` is http(s) and every address its host resolves to is public."""
    parts = urlsplit(str(url))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise WebError("only http and https links can be read")
    if parts.username or parts.password:
        raise WebError("links with a user name or password are not read")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(parts.hostname, parts.port or 443, type=socket.SOCK_STREAM)
    except OSError:
        raise WebError(f"{parts.hostname} cannot be found") from None
    if not infos or not all(_public(info[4][0]) for info in infos):
        raise WebError("that address is not public; only public web pages can be read")
    # ponytail: the address is checked, then httpx resolves it again (DNS rebinding window); pin the IP if that matters.


class _Text(HTMLParser):
    """Readable text of an HTML page: no scripts, styles or navigation."""
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header", "form", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.title, self._skip, self._in_title = [], "", 0, False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag in ("p", "div", "br", "li", "h1", "h2", "h3", "h4", "pre", "tr", "section", "article"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._skip:
            self.parts.append(data)


def html_text(html):
    p = _Text()
    p.feed(html)
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(p.parts))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return " ".join(p.title.split()), text


async def fetch(url, max_chars=MAX_PAGE_CHARS):
    """{"url", "title", "text"} of a public page. Redirects are followed by hand, each one checked."""
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False,
                                 headers={"User-Agent": USER_AGENT}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            await check_url(url)
            try:
                async with client.stream("GET", url) as r:
                    if r.is_redirect and r.headers.get("location"):
                        url = urljoin(str(r.url), r.headers["location"])
                        continue
                    if r.status_code >= 400:
                        raise WebError(f"the page answered HTTP {r.status_code}")
                    kind = r.headers.get("content-type", "").split(";")[0].strip().lower()
                    if kind and not (kind.startswith("text/") or kind in ("application/json", "application/xhtml+xml")):
                        raise WebError(f"not a text page ({kind})")
                    body = b""
                    async for chunk in r.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_PAGE_BYTES:
                            break
                    text = body[:MAX_PAGE_BYTES].decode(r.encoding or "utf-8", errors="replace")
            except httpx.HTTPError as e:
                raise WebError(f"the page could not be read ({type(e).__name__})") from None
            title, text = html_text(text) if "html" in kind or not kind else ("", text)
            return {"url": str(url), "title": title[:200], "text": text[:max_chars]}
    raise WebError("too many redirects")


async def call(base_url, name, args):
    """Run a web tool for an agent. Returns a dict; errors come back as {"error": ...}."""
    try:
        if name == "web_search":
            return {"results": await search(base_url, args.get("query"), args.get("limit"))}
        if name == "fetch_url":
            return await fetch(str(args.get("url", "")))
    except WebError as e:
        return {"error": str(e)}
    return {"error": f"unknown tool {name}"}
