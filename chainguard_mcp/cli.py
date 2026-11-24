"""
CLI & Stdio MCP Server entrypoint (`python -m chainguard_mcp`).
"""
from __future__ import annotations

import argparse
import json
import sys

from . import (
    DEFAULT_MCP_URL,
    INSTANT_PASS_URL,
    ChainGuardRemoteClient,
    handle_mcp_message,
    inspect_mcp_text,
    inspect_tx_calldata,
)


def run_stdio_mcp(*, mcp_url: str = DEFAULT_MCP_URL, api_key: str = "", offline: bool = False) -> int:
    client = None if offline else ChainGuardRemoteClient(mcp_url=mcp_url, api_key=api_key)
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        resp = handle_mcp_message(msg, mcp_url=mcp_url, api_key=api_key, offline=offline, client=client)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chainguard-mcp",
        description="ChainGuard Web3 Security, DeFi Yield, Vault Recovery & Non-Custodial USDT MCP Server",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_mcp = sub.add_parser("mcp", help="Run stdio MCP server (bridges to remote 14-tool MCP or local --offline firewall)")
    p_mcp.add_argument("--url", default=DEFAULT_MCP_URL)
    p_mcp.add_argument("--api-key", default="")
    p_mcp.add_argument("--offline", action="store_true")

    p_tx = sub.add_parser("scan-tx", help="Inspect EVM calldata offline for unlimited approvals, Permit2, or proxy upgrades")
    p_tx.add_argument("calldata")
    p_tx.add_argument("--to", default="")

    p_txt = sub.add_parser("scan-mcp", help="Inspect prompt/tool text offline for Unicode smuggling, injections, or keypair leaks")
    p_txt.add_argument("text")

    p_tools = sub.add_parser("tools", help="List live remote MCP tools and the $9 1-Click Monthly Pass link")
    p_tools.add_argument("--url", default=DEFAULT_MCP_URL)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "mcp":
        return run_stdio_mcp(mcp_url=args.url, api_key=args.api_key, offline=args.offline)
    if args.command == "scan-tx":
        res = inspect_tx_calldata(args.calldata, to_address=args.to)
        print(json.dumps(res, indent=2))
        return 2 if res["verdict"] == "BLOCK" else 0
    if args.command == "scan-mcp":
        res = inspect_mcp_text(args.text)
        print(json.dumps(res, indent=2))
        return 2 if res["verdict"] == "BLOCK" else 0
    if args.command == "tools":
        tools = ChainGuardRemoteClient(mcp_url=args.url).list_tools()
        print(json.dumps({"count": len(tools), "tools": [t.get("name") for t in tools], "unlimited_pass_url": INSTANT_PASS_URL}, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
