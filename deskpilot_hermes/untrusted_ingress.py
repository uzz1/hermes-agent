"""Fail-closed inspection of content that originates outside the operator.

Every byte that reaches model context or becomes an action must pass one of the
four ingress functions first. The parent policy process is the only authority
that can allow it; a denial, a malformed reply, or an unreachable parent all
raise rather than returning content.
"""

import hashlib
from typing import Any

from deskpilot_hermes.policy import ParentPolicyClient


class UntrustedContentDenied(PermissionError):
    """Raised instead of returning content the policy gate refused."""


def inspect_untrusted(
    client: ParentPolicyClient, source: str, content: str, user_request: str
) -> str:
    """Return ``content`` only if the parent policy allows it from ``source``.

    The operator's request is forwarded as a digest, never as text: the
    inspector correlates the request without gaining a second copy of it.
    """
    digest = "sha256:" + hashlib.sha256(user_request.encode()).hexdigest()
    reply = client.call(
        "content.inspect",
        {"source": source, "content": content, "userRequestDigest": digest},
    )
    if reply.result is None or reply.result.get("allowed") is not True:
        raise UntrustedContentDenied(
            reply.rule_id if reply.result is None else reply.result["ruleID"]
        )
    return content


def ingest_browseros(client: Any, content: str, user_request: str) -> str:
    return inspect_untrusted(client, "browseros", content, user_request)


def ingest_app_text(client: Any, content: str, user_request: str) -> str:
    return inspect_untrusted(client, "app", content, user_request)


def ingest_tool_output(client: Any, content: str, user_request: str) -> str:
    return inspect_untrusted(client, "tool", content, user_request)


def ingest_remote_instruction(client: Any, content: str, user_request: str) -> str:
    return inspect_untrusted(client, "remote", content, user_request)
