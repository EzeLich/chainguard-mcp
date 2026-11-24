# ChainGuard MCP — 14-Tool Web3 Security, DeFi Yield, Vault Recovery & USDT Payment MCP Server

[![CI](https://github.com/EzeLich/chainguard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/EzeLich/chainguard-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP: 2025-03-26](https://img.shields.io/badge/MCP-Streamable%20HTTP%20%2B%20Stdio-38bdf8.svg)](https://chainguard-studio-production.up.railway.app/mcp)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://python.org)

**Equip Claude Desktop, Cursor, Windsurf, OpenCode & Autonomous AI Agents with 14 Web3 Security Firewalls, EIP-7702 Hijack Detectors, Solana Token-2022 Auditors, DeFiLlama Yield Scanners, Vault Recovery Calldata Builders, and Non-Custodial USDT/USDC Checkout Tools.**

- 🧠 **Live Hosted MCP Endpoint (Zero Install):** `https://chainguard-studio-production.up.railway.app/mcp`
- ⚡ **Instant 1-Click $9 Unlimited Monthly Pass (USDC/USDT Base — Auto-Mints `cg_live_` Key):** [Get Unlimited MCP Pass →](https://chainguard-studio-production.up.railway.app/paygate/pay?merchant=0x4Ed4D0750453C027FA8398067d5af980Bcc9B6eD&amount=9&network=base&title=ChainGuard+Unlimited+MCP+Pass&issue_pass=1&billing_days=30)
- 🌐 **Full Platform & Wallet Recovery:** [https://chainguard-studio-production.up.railway.app](https://chainguard-studio-production.up.railway.app)
- 💳 **Powered by:** [EzeLich/paygate-usdt](https://github.com/EzeLich/paygate-usdt) (`0%` non-custodial USDT/USDC settlement)

---

## 1-Line Remote Setup (Claude Desktop · Cursor · Windsurf · OpenCode)

Connect directly to the hosted Streamable-HTTP MCP server (`2025-03-26` + `2024-11-05` compliant, `tools`, `resources`, `prompts`, free tier: 5 calls/hour with zero signup):

```json
{
  "mcpServers": {
    "chainguard-firewall": {
      "url": "https://chainguard-studio-production.up.railway.app/mcp"
    }
  }
}
```

Or run the **Zero-Dependency Local Stdio Bridge + Offline Pre-Flight Firewall** via `pip` / `uvx`:

```bash
pip install git+https://github.com/EzeLich/chainguard-mcp.git
chainguard-mcp mcp
# Or deterministic offline security firewall with zero network calls:
chainguard-mcp mcp --offline
```

```json
{
  "mcpServers": {
    "chainguard-firewall": {
      "command": "chainguard-mcp",
      "args": ["mcp"],
      "env": {
        "CHAINGUARD_API_KEY": "cg_live_optional_for_unlimited_calls"
      }
    }
  }
}
```

---

## All 14 Live MCP Tools

| Tool | Category | What It Does |
|---|---|---|
| `check_eip7702_delegation` | EVM Security | Detect active EIP-7702 EOA delegation hijacks (`0xef0100...`) on Ethereum, Base, Arbitrum, or Polygon |
| `check_solana_token2022` | Solana Security | Inspect SPL / Token-2022 mint for `PermanentDelegate` drainers, TransferHooks, Mint/Freeze authority & Rug signals |
| `check_tx_firewall` | Pre-Flight Firewall | Inspect EVM calldata for unlimited `MAX_UINT256` approvals, `setApprovalForAll`, Permit2, and proxy upgrades |
| `check_mcp_poisoning` | Agent Safety | Detect hidden zero-width Unicode smuggling, prompt injections, and raw 64-byte keypair leaks |
| `audit_solidity_or_mcp` | Code & Config Audit | Instant vulnerability triage for Solidity contracts or MCP/AI agent configs |
| `check_frontend_hijack` | Frontend Security | Inspect DeFi frontend URLs & EIP-1967 proxies for missing CSP/SRI or script hijacks |
| `scan_evm_dust_and_hygiene` | Vault Recovery | Zero-connect multi-chain EVM scan across Base, Arbitrum, Optimism, Polygon & Ethereum |
| `reclaim_solana_rent` | Vault Recovery | Scan Solana wallets for trapped SOL rent in empty 0-balance SPL/Token-2022 accounts & build unsigned Close tx |
| `build_evm_dust_to_usdt_sweep` | Non-Custodial DeFi | Build exact-amount `approve` + audited KyberSwap/OpenOcean calldata to sweep dust into USDT/USDC |
| `build_cross_chain_consolidation` | Cross-Chain DeFi | Build 1-click LI.FI Diamond consolidation calldata bridging tokens across EVM L2s |
| `find_best_defi_yields` | DeFi Alpha | Scan 15,000+ live DeFiLlama pools ranked by risk-adjusted APY |
| `analyze_token_alpha` | Trading Alpha | Pre-trade EVM & Solana token intel combining live DexScreener price, liquidity, FDV & 24h volume |
| `create_usdt_invoice` | Payments (`PayGate`) | Create non-custodial multi-chain USDT/USDC checkout invoices settling 100% straight to your wallet |
| `verify_usdt_invoice` | Payments (`PayGate`) | Verify on-chain USDT/USDC tx hashes against an invoice ID via live JSON-RPC |

---

## Offline CLI Firewall

Audit transaction calldata or MCP tool payloads right in CI/CD or pre-commit hooks with **zero API keys**:

```bash
chainguard-mcp scan-tx 0x095ea7b30000000000000000000000004ed4d0750453c027fa8398067d5af980bcc9b6edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
chainguard-mcp scan-mcp "Analyze token safety"
chainguard-mcp tools
```

---

## Upgrade Limits & Managed Plans (100% Non-Custodial USDC/USDT)

- **Free Tier (`$0`)**: **5 MCP tool calls/hour** per IP + unlimited offline CLI scans (`scan-tx`, `scan-mcp`, `--offline`).
- **Unlimited Monthly MCP & Pro API Pass (`$9 USDC/USDT`, 30 days)**: Auto-mints your `cg_live_...` key immediately upon on-chain confirmation -> [⚡ Activate 1-Click Base USDC/USDT Pass](https://chainguard-studio-production.up.railway.app/paygate/pay?merchant=0x4Ed4D0750453C027FA8398067d5af980Bcc9B6eD&amount=9&network=base&title=ChainGuard+Unlimited+MCP+Pass&issue_pass=1&billing_days=30).
- **Custom Enterprise Security / White-Label MCP Deployment (`$199–$499 USDT`)**: [Launch PayGate Checkout](https://chainguard-studio-production.up.railway.app/paygate#b2b).

## Local Testing

```bash
git clone https://github.com/EzeLich/chainguard-mcp.git
cd chainguard-mcp
pip install -e ".[dev]"
pytest -v
```
