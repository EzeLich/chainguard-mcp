"""
ChainGuard MCP — 14-Tool Web3 Security, DeFi Yield, Vault Recovery & Non-Custodial USDT Bridge.
Provides offline deterministic EVM calldata / MCP poisoning firewalls plus a zero-dependency
Stdio-to-Streamable-HTTP bridge to https://chainguard-studio-production.up.railway.app/mcp.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

DEFAULT_MCP_URL = "https://chainguard-studio-production.up.railway.app/mcp"
INSTANT_PASS_URL = (
    "https://chainguard-studio-production.up.railway.app/paygate/pay"
    "?merchant=0x4Ed4D0750453C027FA8398067d5af980Bcc9B6eD"
    "&amount=9&network=base&title=ChainGuard+Unlimited+MCP+Pass&issue_pass=1&billing_days=30"
)

_ZW_CHARS = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u202e", "\u202d")
_SOL_KEYPAIR_RE = re.compile(r"\[(?:\s*(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\s*,){63}\s*(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\s*\]")
_SECRET_RE = re.compile(r"\b(?:gh" + r"p|gho|ghu|ghs|ghr|sk_live|whsec)_[A-Za-z0-9]{16,}\b")

REMOTE_TOOL_NAMES: tuple[str, ...] = (
    "check_eip7702_delegation",
    "check_solana_token2022",
    "check_tx_firewall",
    "check_mcp_poisoning",
    "audit_solidity_or_mcp",
    "reclaim_solana_rent",
    "check_frontend_hijack",
    "scan_evm_dust_and_hygiene",
    "build_evm_dust_to_usdt_sweep",
    "build_cross_chain_consolidation",
    "find_best_defi_yields",
    "analyze_token_alpha",
    "create_usdt_invoice",
    "verify_usdt_invoice",
)


def inspect_tx_calldata(calldata: str, to_address: str = "") -> dict[str, Any]:
    """Deterministic offline pre-flight check for EVM drainer & proxy calldata."""
    data = (calldata or "").strip().lower()
    if data and not data.startswith("0x"):
        data = "0x" + data
    alerts: list[dict[str, Any]] = []
    risk_score = 0

    selector = data[:10] if len(data) >= 10 else ""
    if selector == "0x095ea7b3":
        if "f" * 32 in data[10:]:
            risk_score += 75
            alerts.append({"id": "TX-MAX-APPROVE", "severity": "CRITICAL", "detail": "Unlimited ERC-20 approve(MAX_UINT256) allowance detected."})
        else:
            risk_score += 15
            alerts.append({"id": "TX-APPROVE", "severity": "INFO", "detail": "Finite ERC-20 approve() allowance call."})
    elif selector == "0xa22cb465":
        if data.endswith("0" * 63 + "1") or "0" * 63 + "1" in data[-64:]:
            risk_score += 70
            alerts.append({"id": "TX-SET-APPROVAL-ALL", "severity": "CRITICAL", "detail": "NFT setApprovalForAll(operator, true) grants full collection control."})
    elif selector in {"0xd505accf", "0x8fcbaf0c", "0x30f28b7a"}:
        risk_score += 55
        alerts.append({"id": "TX-PERMIT-SPEND", "severity": "HIGH", "detail": "Gasless Permit/Permit2 approval selector detected."})
    elif selector in {"0x3659cfe6", "0x4f1ef286"}:
        risk_score += 65
        alerts.append({"id": "TX-PROXY-UPGRADE", "severity": "HIGH", "detail": "UUPS/Transparent proxy upgrade selector detected."})

    risk_score = min(100, risk_score)
    verdict = "BLOCK" if risk_score >= 50 else ("WARN" if risk_score >= 25 else "ALLOW")
    return {
        "mode": "offline_preflight",
        "to_address": to_address,
        "selector": selector or None,
        "verdict": verdict,
        "risk_score": risk_score,
        "alerts": alerts,
        "pass_url": INSTANT_PASS_URL,
    }


def inspect_mcp_text(text: str) -> dict[str, Any]:
    """Deterministic offline scanner for zero-width Unicode poisoning, prompt injection, and leaked keys."""
    body = text or ""
    low = body.lower()
    alerts: list[dict[str, Any]] = []
    risk_score = 0

    zw_count = sum(body.count(ch) for ch in _ZW_CHARS)
    if zw_count > 0:
        risk_score += 55
        alerts.append({"id": "MCP-UNI-ZW", "severity": "CRITICAL", "detail": f"Detected {zw_count} invisible zero-width/bidi characters."})

    if any(p in low for p in ("ignore previous instructions", "exfiltrate", "system prompt", "private_key", "seed phrase")):
        risk_score += 65
        alerts.append({"id": "MCP-PROMPT-INJECT", "severity": "CRITICAL", "detail": "Prompt injection or credential exfiltration phrase detected."})

    if _SOL_KEYPAIR_RE.search(body):
        risk_score += 80
        alerts.append({"id": "DRAIN-SOL-BYTES", "severity": "CRITICAL", "detail": "Raw 64-byte Solana keypair array exposed."})

    if _SECRET_RE.search(body):
        risk_score += 75
        alerts.append({"id": "SECRET-TOKEN-LEAK", "severity": "CRITICAL", "detail": "API token / signing secret pattern detected."})

    risk_score = min(100, risk_score)
    verdict = "BLOCK" if risk_score >= 50 else ("WARN" if risk_score >= 25 else "ALLOW")
    return {
        "mode": "offline_mcp_firewall",
        "verdict": verdict,
        "risk_score": risk_score,
        "alerts": alerts,
        "pass_url": INSTANT_PASS_URL,
    }


class ChainGuardRemoteClient:
    """Thin JSON-RPC 2.0 client for the hosted ChainGuard Firewall & PayGate MCP server."""

    def __init__(self, mcp_url: str = DEFAULT_MCP_URL, api_key: str = "", timeout_s: float = 20.0) -> None:
        self.mcp_url = mcp_url.strip() or DEFAULT_MCP_URL
        self.api_key = (api_key or os.environ.get("CHAINGUARD_API_KEY", "")).strip()
        self.timeout_s = float(timeout_s)

    def post_jsonrpc(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "chainguard-mcp/1.0.0",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        req = urllib.request.Request(
            self.mcp_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read().decode("utf-8").strip()
                if resp.status == 202 or not raw:
                    return resp.status, None
                return resp.status, json.loads(raw)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
                return exc.code, parsed
            except Exception:
                return exc.code, {
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "error": {"code": -32000, "message": body or f"HTTP {exc.code}"},
                }

    def list_tools(self) -> list[dict[str, Any]]:
        _, res = self.post_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        return list(((res or {}).get("result") or {}).get("tools") or [])


def _offline_tools_schema() -> list[dict[str, Any]]:
    return [
        {
            "name": "check_tx_firewall",
            "description": "Offline EVM transaction drainer & unlimited ERC-20 approval inspector.",
            "inputSchema": {
                "type": "object",
                "properties": {"to": {"type": "string"}, "data": {"type": "string"}},
                "required": ["data"],
            },
        },
        {
            "name": "check_mcp_poisoning",
            "description": "Offline hidden zero-width Unicode smuggling & prompt injection detector.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        },
    ]


def handle_mcp_message(
    msg: dict[str, Any],
    *,
    mcp_url: str = DEFAULT_MCP_URL,
    api_key: str = "",
    offline: bool = False,
    client: ChainGuardRemoteClient | None = None,
) -> dict[str, Any] | None:
    """Handle one JSON-RPC 2.0 MCP message offline or bridged to ChainGuard Remote MCP."""
    method = str(msg.get("method") or "")
    rpc_id = msg.get("id")
    params = msg.get("params") or {}

    if method.startswith("notifications/"):
        if not offline:
            try:
                (client or ChainGuardRemoteClient(mcp_url=mcp_url, api_key=api_key)).post_jsonrpc(msg)
            except Exception:
                pass
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

    if not offline:
        rpc_client = client or ChainGuardRemoteClient(mcp_url=mcp_url, api_key=api_key)
        try:
            _, res = rpc_client.post_jsonrpc(msg)
            return res
        except Exception as exc:
            if method == "tools/call":
                name = str(params.get("name") or "")
                args = params.get("arguments") or {}
                if name == "check_tx_firewall":
                    out = inspect_tx_calldata(str(args.get("data") or ""), str(args.get("to") or ""))
                    return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}}
                if name == "check_mcp_poisoning":
                    out = inspect_mcp_text(str(args.get("text") or ""))
                    return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}}
            return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32001, "message": f"Remote MCP unreachable: {exc}"}}

    # Pure deterministic offline mode
    if method == "initialize":
        req_proto = str(params.get("protocolVersion") or "2025-03-26")
        supported = {"2025-06-18", "2025-03-26", "2024-11-05"}
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": req_proto if req_proto in supported else "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}, "resources": {"subscribe": False, "listChanged": False}, "prompts": {"listChanged": False}},
                "serverInfo": {"name": "chainguard-mcp", "version": "1.0.0"},
                "instructions": f"Offline local security firewall mode active. Full 14-tool remote MCP: {mcp_url} | $9 Monthly Pass: {INSTANT_PASS_URL}",
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": _offline_tools_schema()}}
    if method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "resources": [
                    {
                        "uri": "chainguard://pass",
                        "name": "ChainGuard $9 Unlimited MCP Pass",
                        "description": "1-Click USDC/USDT checkout for unlimited remote MCP & API calls.",
                        "mimeType": "text/plain",
                    }
                ]
            },
        }
    if method == "prompts/list":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "prompts": [
                    {"name": "preflight_scan_tx", "description": "Inspect EVM calldata for unlimited approvals or proxy upgrades."}
                ]
            },
        }
    if method == "tools/call":
        name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        if name == "check_tx_firewall":
            out = inspect_tx_calldata(str(args.get("data") or ""), str(args.get("to") or ""))
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}}
        if name == "check_mcp_poisoning":
            out = inspect_mcp_text(str(args.get("text") or ""))
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}}
        return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": f"Tool {name} requires remote mode (omit --offline)"}}

    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


__all__ = [
    "ChainGuardRemoteClient",
    "DEFAULT_MCP_URL",
    "INSTANT_PASS_URL",
    "REMOTE_TOOL_NAMES",
    "handle_mcp_message",
    "inspect_mcp_text",
    "inspect_tx_calldata",
]
