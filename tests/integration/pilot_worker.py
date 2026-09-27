"""TEST ONLY worker entrypoint: real actor/DB/Redis, controlled Slack transport.

Not imported by any application module. Every action is forced through an
in-memory HTTP transport; this harness cannot deliver to a live connector.
"""

import json
import os
from pathlib import Path
from unittest.mock import patch

import httpx

from nlw.engine.actions import ActionExecResult, ActionTask, run_action
from nlw.worker.actors import advance_run, ping  # noqa: F401


def _reply(request: httpx.Request) -> httpx.Response:
    assert str(request.url) == "https://slack.com/api/chat.postMessage"
    evidence = os.environ.get("PILOT_DELIVERY_EVIDENCE")
    if evidence:
        # Synthetic message and channel only. Never headers or credentials.
        with Path(evidence).open("a") as stream:
            stream.write(json.dumps(json.loads(request.content)) + "\n")
    if os.environ.get("PILOT_DELIVERY_OUTCOME") == "unknown":
        return httpx.Response(500)
    return httpx.Response(200, json={"ok": True, "channel": "CPILOT", "ts": "1"})


def controlled_action(task: ActionTask) -> ActionExecResult:
    return run_action(task, transport=httpx.MockTransport(_reply))


patch("nlw.engine.execution.run_action", controlled_action).start()
