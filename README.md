# KeeperPAM Gateway Network Path Tester

Verifies that all **required network paths are open** between this machine and Keeper's cloud infrastructure before deploying a KeeperPAM Gateway. Run this first — if any path is blocked, the Gateway will fail silently or partially after installation.

Implemented as a `keeper gateway-tester` command for [Keeper Commander](https://github.com/Keeper-Security/Commander).

**Zero-knowledge** — no vault data leaves the machine. Every test is an outbound-only probe; nothing is sent to Keeper except standard protocol handshakes.

## Why run this?

KeeperPAM Gateways require several distinct outbound network paths to function:

| Path | Purpose | What breaks without it |
|---|---|---|
| DNS + HTTPS to `keepersecurity.{region}` | Vault API | Gateway cannot authenticate or sync |
| WSS to `connect.keepersecurity.{region}:443` | Real-time control channel | Gateway connects but receives no commands |
| TCP 3478 to `krelay` | STUN/TURN relay setup | Session negotiation fails |
| UDP 3478 to `krelay` | STUN binding / external IP discovery | NAT traversal broken |
| UDP 49152–65535 to `krelay` | WebRTC media (RDP, SSH audio/video) | Sessions connect but screen/audio blank |
| TCP 636 to your LDAP server | LDAPS authentication | AD/LDAP login fails for PAM targets |

Corporate firewalls, proxies, and cloud security groups commonly block one or more of these — especially UDP ports. This tool identifies exactly which paths are open or blocked before you spend time troubleshooting a live Gateway.

## What it tests

| Group | Test | Protocol | Port |
|---|---|---|---|
| DNS & Cloud | DNS resolution → Keeper API | UDP | 53 |
| DNS & Cloud | HTTPS API reachable | TCP/TLS | 443 |
| DNS & Cloud | WebSocket control channel reachable | TCP/WSS | 443 |
| STUN / TURN | TCP STUN binding — confirms TCP path + returns external IP | TCP | 3478 |
| STUN / TURN | UDP STUN binding — confirms outbound UDP + returns external IP | UDP | 3478 |
| STUN / TURN | TURN relay reachability — unauthenticated Allocate → expects 401, confirming end-to-end relay path | UDP | 3478 |
| WebRTC Media | 8 sampled ports open across media range | UDP | 49152–65535 |
| LDAPS (optional) | TCP port open + TLS cert valid + expiry check | TCP/TLS | 636 |

Source: [KeeperPAM Gateway Network Configuration](https://docs.keeper.io/en/keeperpam/privileged-access-manager/references/gateway-network-configuration)

## Installation

Drop `network_test.py` into your Commander `commands/` directory:

```bash
cp network_test.py $(python3 -c "import keepercommander; print(__import__('os').path.dirname(keepercommander.__file__))")/commands/
```

Then register the command in `keepercommander/commands/base.py` inside `register_commands()`, after `toggle_pam_legacy_commands(legacy=False)`:

```python
from .network_test import NetworkTestCommand
commands['gateway-tester'] = NetworkTestCommand()
command_info['gateway-tester'] = 'Test network connectivity requirements for KeeperPAM'
```

## Usage

```bash
# Basic — tests US region, no LDAP
keeper gateway-tester

# Specific region
keeper gateway-tester --region eu

# Include LDAP server path check
keeper gateway-tester --ldap-host ldap.yourcompany.com

# Save results for a support ticket or change request
keeper gateway-tester --json | tee connectivity-report.json

# Verbose — show raw error messages
keeper gateway-tester -v
```

### Regions

| Flag | Domain | Location |
|---|---|---|
| `us` (default) | keepersecurity.com | United States |
| `eu` | keepersecurity.eu | European Union |
| `au` | keepersecurity.com.au | Australia |
| `jp` | keepersecurity.jp | Japan |
| `ca` | keepersecurity.ca | Canada |
| `gov` | keepersecurity.us | GovCloud |

## Auto-detection (logged-in mode)

When run after `keeper login`, the command automatically reads your session to:

- **Detect your region** from the vault server URL — no `--region` flag needed
- **Find your LDAP host** from PAM Configuration records in your vault — no `--ldap-host` flag needed

```
╔════════════════════════════════════════════════════════════╗
║       KeeperPAM  ·  Gateway Network Readiness Tester       ║
╚════════════════════════════════════════════════════════════╝
  Vault    you@company.com
  Region   US (auto-detected)  ·  keepersecurity.com
  LDAP     auto-detected from PAM config
  Date     2026-03-14  22:45 UTC
```

## Sample output

All paths open:

```
╔════════════════════════════════════════════════════════════╗
║       KeeperPAM  ·  Gateway Network Readiness Tester       ║
╚════════════════════════════════════════════════════════════╝
  Tip: run 'keeper login' first to auto-detect region and LDAP
  Region   US  ·  keepersecurity.com
  Date     2026-03-14  23:22 UTC

  ▸  DNS & Cloud Connectivity
  ────────────────────────────────────────────────────────────
    ✓  DNS  keepersecurity.com  ·  →  100.25.27.45
    ✓  HTTPS API  keepersecurity.com:443  ·  HTTP 200
    ✓  WebSocket  connect.keepersecurity.com:443  ·  HTTP 401

  ▸  STUN / TURN  ·  krelay.keepersecurity.com
  ────────────────────────────────────────────────────────────
    ✓  TCP STUN  krelay.keepersecurity.com:3478  ·  external IP  107.23.98.184
    ✓  UDP STUN  krelay.keepersecurity.com:3478  ·  external IP  107.23.98.184
    ✓  TURN relay  krelay.keepersecurity.com:3478  ·  reachable · auth required

  ▸  WebRTC Media Ports  ·  UDP 49152–65535
  ────────────────────────────────────────────────────────────
    ✓ 49152   ✓ 50000   ✓ 52000   ✓ 55000   ✓ 58000   ✓ 61000   ✓ 63000   ✓ 65535
    ✓  8/8 sampled ports reachable

  ════════════════════════════════════════════════════════════
    ✓  GATEWAY READY  ·  14 / 14 checks passed
  ════════════════════════════════════════════════════════════
```

## Requirements

- Python 3.8+
- Keeper Commander 16.x+
- `requests`, `websockets`, `colorama` (all standard Commander dependencies)

## Known limitations

- WebRTC port tests sample 8 ports from the 49152–65535 range rather than all 16,383.
