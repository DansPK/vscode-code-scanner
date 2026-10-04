"""Test doubles."""

import json

GOOD_REVIEW = {"verdict": "likely_real", "explanation": "User input reaches the query.",
               "fix_recommendation": "Use a parameterised query.", "suggested_patch": "cur.execute('...?', (name,))"}


NO_ACTION = {"action": "none", "full": False, "paths": [], "url": None, "sure": True}


def is_intent_call(messages):
    return messages and str(messages[0].get("content", "")).startswith("You route messages")


class FakeLLMCompletion:
    """Returns replies from a list (or a function of the messages), and records every call.
    The chat's routing call ("what does this message want?") is answered from `intents`
    (a list, used in order; default: no action) and is recorded in `intent_calls`, not `calls`."""

    def __init__(self, replies=None, fn=None, intents=None):
        self.replies = list(replies or [])
        self.fn = fn
        self.intents = list(intents or [])
        self.calls = []
        self.intent_calls = []

    async def __call__(self, messages, tools=None):
        if is_intent_call(messages):
            self.intent_calls.append([dict(m) for m in messages])
            decision = self.intents.pop(0) if self.intents else NO_ACTION
            return {"content": json.dumps({**NO_ACTION, **decision}), "tool_calls": []}
        self.calls.append({"messages": [dict(m) for m in messages], "tools": tools})
        if self.fn:
            return self.fn(messages, tools)
        r = self.replies.pop(0) if self.replies else json.dumps(GOOD_REVIEW)
        return r if isinstance(r, dict) else {"content": r, "tool_calls": []}
