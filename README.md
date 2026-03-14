# KeeperPAM Gateway Network Readiness Tester

A `keeper gateway-tester` command for [Keeper Commander](https://github.com/Keeper-Security/Commander) that validates all network connectivity requirements for a KeeperPAM deployment.

**Zero-knowledge** — no vault data leaves the machine. All tests are outbound-only probes.

## What it tests

| Group | Test | Protocol |
|---|---|---|
| DNS & Cloud | DNS resolution for Keeper API | UDP 53 |
| DNS & Cloud | HTTPS API (`keepersecurity.{region}:443`) | TCP/TLS |
| DNS & Cloud | WebSocket router (`connect.keepersecurity.{region}:443`) | TCP/WSS |
| STUN / TURN | TCP port 3478 reachable (`krelay`) | TCP |
| STUN / TURN | UDP STUN binding — returns your external IP | UDP 3478 |
| WebRTC Media | 5 sampled ports across 49152–65535 range | UDP |
| LDAPS (optional) | TCP + TLS cert inspection, expiry warning | TCP/TLS |

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

# Include LDAP server check
keeper gateway-tester --ldap-host ldap.yourcompany.com

# Machine-readable JSON (for support tickets or automation)
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

When run after `keeper login`, the command automatically:

- **Detects your region** from the vault server URL — no `--region` flag needed
- **Finds your LDAP host** from any PAM Configuration records in your vault — no `--ldap-host` flag needed

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
    ✓  WebSocket  connect.keepersecurity.com:443  ·  reachable

  ▸  STUN / TURN  ·  krelay.keepersecurity.com
  ────────────────────────────────────────────────────────────
    ✓  TCP 3478  krelay.keepersecurity.com  ·  port open
    ✓  UDP STUN  krelay.keepersecurity.com:3478  ·  external IP  107.23.98.184

  ▸  WebRTC Media Ports  ·  UDP 49152–65535
  ────────────────────────────────────────────────────────────
    ✓ 49152   ✓ 52000   ✓ 55000   ✓ 60000   ✓ 65535
    ✓  5/5 sampled ports reachable

  ════════════════════════════════════════════════════════════
    ✓  GATEWAY READY  ·  10 / 10 checks passed
  ════════════════════════════════════════════════════════════
```

## Requirements

- Python 3.8+
- Keeper Commander 16.x+
- `requests`, `websockets`, `colorama` (all standard Commander dependencies)

## Known limitations

- UDP STUN probes use IPv4 only (`AF_INET`). IPv6-only networks will show UDP failures.
- WebRTC port tests sample 5 ports from the 49152–65535 range rather than all 16,383.
- The WebSocket test checks TCP reachability; a full authenticated connection requires being logged in (future enhancement).
