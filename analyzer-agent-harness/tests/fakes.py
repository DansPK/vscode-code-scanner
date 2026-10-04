"""Test doubles."""

import json

GOOD_REVIEW = {"verdict": "likely_real", "explanation": "User input reaches the query.",
               "fix_recommendation": "Use a parameterised query.", "suggested_patch": "cur.execute('...?', (name,))"}


class FakeLLMCompletion:
    """Returns replies from a list (or a function of the messages), and records every call."""

    def __init__(self, replies=None, fn=None):
        self.replies = list(replies or [])
        self.fn = fn
        self.calls = []

    async def __call__(self, messages, tools=None):
        self.calls.append({"messages": [dict(m) for m in messages], "tools": tools})
        if self.fn:
            return self.fn(messages, tools)
        r = self.replies.pop(0) if self.replies else json.dumps(GOOD_REVIEW)
        return r if isinstance(r, dict) else {"content": r, "tool_calls": []}
