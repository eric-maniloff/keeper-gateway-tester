# gateway-tester: Simulation Mode + Rock-Solid Enhancements

**Date:** 2026-03-15
**File:** `keepercommander/commands/network_test.py`

---

## Problem

SEs demo `keeper gateway-tester` to prospects before the prospect has a live network path to Keeper.
There is no way to show what the output looks like without real connectivity, and no way to demonstrate
failure scenarios (blocked UDP, TLS proxy intercept, etc.) without actually breaking the network.

Additionally, the current implementation has robustness gaps:
- No explicit DNS test for `krelay` (only implicit via TCP/UDP)
- UDP STUN probes fail on a single packet loss (no retry)
- All group 1 tests run sequentially (~15s wall time)
- No user-controllable timeout

---

## Goals

1. `--simulate` flag: run command with fake results, no real I/O, labeled "EXAMPLE OUTPUT"
2. Named scenario presets covering the most common real-world failure patterns
3. Freeform per-group overrides to layer on top of any preset
4. Four robustness enhancements bundled alongside simulation

---

## CLI Interface

```
keeper gateway-tester --simulate [SCENARIO]
                      [--sim-cloud OUTCOME]
                      [--sim-stun OUTCOME]
                      [--sim-webrtc OUTCOME]
                      [--sim-ldap OUTCOME]
                      [--timeout SECONDS]
```

`--simulate` is added to the argument parser with `nargs='?'`, `const='all-pass'`, `default=None`:
```python
network_test_parser.add_argument(
    '--simulate', dest='simulate',
    nargs='?', const='all-pass', default=None,
    metavar='SCENARIO',
    help='Run with fake results (no network I/O). SCENARIO: all-pass (default), '
         'firewall-blocks-udp, proxy-intercepts-tls, no-stun, '
         'gateway-wont-connect, webrtc-degraded, ldap-cert-expiring',
)
```
- `--simulate` alone → `simulate = 'all-pass'`
- `--simulate firewall-blocks-udp` → `simulate = 'firewall-blocks-udp'`
- omitted → `simulate = None` (real tests run)
- `--simulate --sim-cloud fail` → argparse sees `--sim-cloud` as a flag, not a value, so `simulate = 'all-pass'`

`--sim-cloud/stun/webrtc/ldap` without `--simulate` is a **usage error** checked in `execute()`:
`Error: --sim-cloud requires --simulate`. This applies to all four `--sim-*` flags.

### Named presets (SCENARIO)

| Preset | Description |
|---|---|
| `all-pass` | All tests green (default when `--simulate` given alone) |
| `firewall-blocks-udp` | Cloud+TCP pass; UDP STUN + all WebRTC ports blocked |
| `proxy-intercepts-tls` | DNS pass; HTTPS TLS error; WS fail |
| `no-stun` | Cloud pass; TCP 3478 open but UDP STUN no response; WebRTC pass |
| `gateway-wont-connect` | DNS+HTTPS pass; WS blocked; STUN+WebRTC all fail |
| `webrtc-degraded` | Cloud+STUN pass; 2/5 WebRTC ports pass |
| `ldap-cert-expiring` | Everything pass; LDAP cert expires in 12 days |

### Freeform overrides

`--sim-cloud`, `--sim-stun`, `--sim-webrtc`, `--sim-ldap` each accept the outcome strings
defined for their respective group (see "Outcome vocabulary" below). `partial` is only valid for
`--sim-webrtc`; specifying it for any other group is a **usage error**:
`Error: --sim-cloud does not support 'partial'`.

Overrides are merged on top of the preset:
```bash
keeper gateway-tester --simulate firewall-blocks-udp --sim-webrtc pass
keeper gateway-tester --simulate all-pass --sim-ldap warn --ldap-host ldap.acme.com
```

---

## Architecture

### `--timeout` propagation

`execute()` writes a module-level mutable `_timeout: int` before calling any test function:
```python
_timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
```

Every hardcoded `DEFAULT_TIMEOUT` reference is replaced with `_timeout` at these call sites:
- `_stun_udp_probe`: `sock.settimeout(_timeout)`
- `test_dns` / `test_dns_krelay`: wrap `socket.getaddrinfo` with save/restore:
  ```python
  _prev = socket.getdefaulttimeout()
  socket.setdefaulttimeout(_timeout)
  try:
      results = socket.getaddrinfo(...)
  finally:
      socket.setdefaulttimeout(_prev)
  ```
  This avoids the global mutation race when group 1 runs in parallel threads.
- `test_https`: `_requests.get(..., timeout=_timeout)`
- `test_tcp_3478`: `socket.create_connection(..., timeout=_timeout)`
- `test_ldaps`: both `socket.create_connection` calls → `timeout=_timeout`
- `_ws_connect`: `open_timeout=_timeout, close_timeout=_timeout`
- `_ws_connect_authenticated`: same two args → `_timeout`

### Canonical group dict keys

```python
KEY_CLOUD  = "DNS & Cloud Connectivity"
KEY_STUN   = "STUN / TURN"
KEY_WEBRTC = "WebRTC Media Ports"
KEY_LDAP   = "LDAPS"
```

These constants are the literal dict keys in `groups` and the literal keys in JSON output.
Terminal section display titles include the hostname suffix separately. A `_section_title()` helper
maps each key to its full display string:

```python
def _section_title(key: str, krelay: str, ldap_host: str, ldap_port: int) -> str:
    if key == KEY_STUN:
        return f"STUN / TURN  ·  {krelay}"
    if key == KEY_WEBRTC:
        return "WebRTC Media Ports  ·  UDP 49152\u201365535"
    if key == KEY_LDAP:
        return f"LDAPS  ·  {ldap_host}:{ldap_port}"
    return key   # KEY_CLOUD — title is the key itself
```

`execute()` calls `_print_section(_section_title(key, krelay, ldap_host, ldap_port))` before
printing each group's results, while `groups` is keyed by the KEY_* constants.

### Outcome vocabulary per group

#### `KEY_CLOUD` (3 TestResults: DNS, HTTPS, WebSocket)
| Outcome | DNS | HTTPS | WebSocket |
|---|---|---|---|
| `pass` | ✓ `→ 203.0.113.45` | ✓ `HTTP 200` | ✓ `HTTP 401` |
| `ws-fail` | ✓ `→ 203.0.113.45` | ✓ `HTTP 200` | ✗ `timeout (firewall?)` |
| `tls-fail` | ✓ `→ 203.0.113.45` | ✗ `TLS error — possible corporate proxy intercept` | ✗ `timeout (firewall?)` |
| `fail` | ✗ `DNS lookup failed` | ✗ `connection refused or DNS failure` | ✗ `DNS resolution failed` |

#### `KEY_STUN` (3 TestResults: krelay-DNS, TCP-3478, UDP-STUN)
`_SIM_RESULTS[(KEY_STUN, outcome)]` always returns all 3 results including the DNS row.

| Outcome | krelay DNS | TCP 3478 | UDP STUN |
|---|---|---|---|
| `pass` | ✓ `→ 198.51.100.12` | ✓ `port open` | ✓ `external IP 203.0.113.99` |
| `udp-fail` | ✓ `→ 198.51.100.12` | ✓ `port open` | ✗ `no response (firewall?)` |
| `fail` | ✗ `DNS lookup failed` | ✗ `timeout (firewall?)` | ✗ `no response (firewall?)` |

#### `KEY_WEBRTC` (6 TestResults: 5 port results + 1 summary)
| Outcome | Ports | Summary |
|---|---|---|
| `pass` | All 5 ✓ | ✓ `5/5 sampled ports reachable` |
| `partial` | 49152+52000 ✓, 55000+60000+65535 ✗ | ⚠ `2/5 sampled ports reachable` (warning=True) |
| `fail` | All 5 ✗ | ✗ `0/5 sampled ports reachable` |

#### `KEY_LDAP` (2 TestResults: TCP, TLS)
| Outcome | TCP | TLS |
|---|---|---|
| `pass` | ✓ `port open` | ✓ `expires 2027-06-01 (443 days) CN=ldap.example.com` |
| `warn` | ✓ `port open` | ⚠ `expires 2026-03-27 (12 days) rotation recommended` (warning=True) |
| `fail` | ✗ `timeout (firewall?)` | *(skipped — TCP failed)* |

### Complete `_SCENARIOS` mapping

```python
_SCENARIOS = {
    'all-pass': {
        KEY_CLOUD:  'pass',
        KEY_STUN:   'pass',
        KEY_WEBRTC: 'pass',
        KEY_LDAP:   'pass',
    },
    'firewall-blocks-udp': {
        KEY_CLOUD:  'pass',
        KEY_STUN:   'udp-fail',
        KEY_WEBRTC: 'fail',
        KEY_LDAP:   'pass',
    },
    'proxy-intercepts-tls': {
        KEY_CLOUD:  'tls-fail',
        KEY_STUN:   'pass',
        KEY_WEBRTC: 'pass',
        KEY_LDAP:   'pass',
    },
    'no-stun': {
        KEY_CLOUD:  'pass',
        KEY_STUN:   'udp-fail',
        KEY_WEBRTC: 'pass',
        KEY_LDAP:   'pass',
    },
    'gateway-wont-connect': {
        KEY_CLOUD:  'ws-fail',    # DNS+HTTPS pass; only WS blocked
        KEY_STUN:   'fail',
        KEY_WEBRTC: 'fail',
        KEY_LDAP:   'pass',
    },
    'webrtc-degraded': {
        KEY_CLOUD:  'pass',
        KEY_STUN:   'pass',
        KEY_WEBRTC: 'partial',
        KEY_LDAP:   'pass',
    },
    'ldap-cert-expiring': {
        KEY_CLOUD:  'pass',
        KEY_STUN:   'pass',
        KEY_WEBRTC: 'pass',
        KEY_LDAP:   'warn',
    },
}
```

`KEY_LDAP` entries in all non-ldap scenarios are intentionally vestigial — they define what outcome
to use *if* `--ldap-host` is provided alongside the scenario, but the group is suppressed otherwise.

**Known limitation:** running `--simulate proxy-intercepts-tls --ldap-host ldap.acme.com` will show
a green LDAP result even though TLS is supposedly intercepted. The scenario affects only KEY_CLOUD.
Users wanting a blocked-LDAP demo should add `--sim-ldap fail`.

### Simulation layer: `_build_sim_results()`

```python
def _build_sim_results(
    scenario: str,
    overrides: dict,        # {KEY_*: outcome_str}
    domain: str,
    ldap_host: Optional[str],
    ldap_port: int,
) -> Tuple[dict, Optional[str], int]:
    """Returns (groups, effective_ldap_host, effective_ldap_port)."""
```

`krelay` is derived inside: `krelay = f"krelay.keepersecurity.{domain}"`.

The `ldap-cert-expiring` auto-inject is handled **inside** this function. The function returns
the *effective* `(ldap_host, ldap_port)` as part of its return value so callers can use them
for display titles without duplicating the inject logic:

```python
if scenario == 'ldap-cert-expiring' and ldap_host is None:
    ldap_host, ldap_port = 'ldap.example.com', 636
```

Steps:
1. Apply `ldap-cert-expiring` auto-inject (above)
2. Load base outcomes from `_SCENARIOS[scenario]`
3. Merge `overrides` (overrides win)
4. For each key in `[KEY_CLOUD, KEY_STUN, KEY_WEBRTC, KEY_LDAP]`:
   - **Skip `KEY_LDAP` first** if `ldap_host is None` — before any `_SIM_RESULTS` lookup
   - Look up `_SIM_RESULTS[(key, outcome)]` → `List[TestResult]`
5. Return `(groups, ldap_host, ldap_port)`

### `execute()` simulation path

```python
if simulate:
    groups, ldap_host, ldap_port = _build_sim_results(scenario, overrides, domain, ldap_host, ldap_port)
    all_results = [r for g in groups.values() for r in g]
    countable   = [r for r in all_results if 'sampled' not in r.name]
    total_passed   = sum(1 for r in countable if r.passed)
    total_checks   = len(countable)
    total_warnings = sum(1 for r in countable if r.warning)
    if json_output:
        render_json(domain, region, groups, total_passed, total_checks,
                    total_warnings, ctx, simulated=True)
    else:
        _print_banner(domain, region, ctx, simulated=True)
        for key, results in groups.items():
            _print_section(_section_title(key, krelay, ldap_host or '', ldap_port))
            if key == KEY_WEBRTC:
                _print_webrtc_results(results)
            else:
                for r in results:
                    _print_result(r)
        _print_summary(total_passed, total_checks, total_warnings)
    return
```

### Banner and JSON changes for simulation

**Terminal:** `_print_banner` gains a `simulated: bool = False` parameter. When `True`, adds
after the title box:
```
  ★  EXAMPLE OUTPUT  ·  no real network calls were made
```

**JSON:** `render_json` gains a `simulated: bool = False` parameter. When `True`, adds
`"simulated": true` to the root output object. The updated signature:
```python
def render_json(domain, region, groups, total_passed, total_checks,
                total_warnings, ctx=None, simulated: bool = False) -> None:
```

---

## Robustness Enhancements

### 1. krelay DNS test

Add `test_dns_krelay(domain: str, verbose: bool) -> TestResult` as the **first result** in
`KEY_STUN` group (before TCP 3478 and UDP STUN). `TestResult.name = f"DNS  krelay.keepersecurity.{domain}"`.
Resolves via `socket.getaddrinfo` with save/restore timeout (same pattern as `test_dns`).

### 2. UDP STUN retry

`_stun_udp_probe` retries once on `socket.timeout`. The socket is created **once before the loop**
and closed **once after it** (in the existing `finally: sock.close()` block). The retry simply
re-sends on the same open socket:

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.settimeout(_timeout)
    if bind_port is not None:
        sock.bind(('', bind_port))
    for attempt in range(2):
        try:
            sock.sendto(_build_stun_request(), (host, port))
            data, _ = sock.recvfrom(1024)
            # parse and return on success
            break
        except socket.timeout:
            if attempt == 1:
                return False, "no response (firewall?)"
finally:
    sock.close()
```

### 3. `--timeout` flag

```
--timeout SECONDS   Per-probe timeout in seconds (default: 5)
```

See propagation details in "Architecture" section above.

### 4. Parallel group 1 execution

Applied to **both** terminal and JSON paths.

`ws_fn` and its arguments are selected before the pool based on `logged_in`:

```python
# test_websocket(domain, verbose)
# test_websocket_authenticated(domain, params, verbose)
if logged_in:
    ws_args = (domain, params, verbose)
    ws_fn   = test_websocket_authenticated
else:
    ws_args = (domain, verbose)
    ws_fn   = test_websocket
```

```python
from concurrent.futures import ThreadPoolExecutor

_print_section(title)   # terminal path: section header and divider print immediately
with ThreadPoolExecutor(max_workers=3) as pool:
    f_dns   = pool.submit(test_dns, domain, verbose)
    f_https = pool.submit(test_https, domain, verbose)
    f_ws    = pool.submit(ws_fn, *ws_args)
    g1 = [f_dns.result(), f_https.result(), f_ws.result()]
for r in g1:
    _print_result(r)    # terminal path: results print as a batch when all three complete
```

Since pool worker threads are **not** the Commander event loop thread, `test_websocket` /
`test_websocket_authenticated` hit the `loop is None` branch and call `asyncio.run()` directly —
no nested loop issue.

**Intentional tradeoff:** group 1 results print as a batch after all three complete, not one by one.
The section header and divider appear immediately; results follow ~5s later. Groups 2–4 retain
per-result streaming. Expected group 1 wall time: ≤ max(dns, https, ws latency) + 0.5s overhead.

---

## Files Changed

| File | Change |
|---|---|
| `keepercommander/commands/network_test.py` | All changes — simulation layer, enhancements, new args |

No new files. No new dependencies.

---

## Test Plan

1. `keeper gateway-tester --simulate` — all-pass, 10+ checks, EXAMPLE OUTPUT banner, no network I/O
2. `keeper gateway-tester --simulate firewall-blocks-udp` — UDP STUN + WebRTC red; cloud+krelay DNS green
3. `keeper gateway-tester --simulate gateway-wont-connect` — cloud DNS+HTTPS green, WS red; STUN+WebRTC all red
4. `keeper gateway-tester --simulate webrtc-degraded` — 2/5 WebRTC partial, yellow ⚠ summary
5. `keeper gateway-tester --simulate proxy-intercepts-tls` — HTTPS TLS error; DNS passes; STUN green
6. `keeper gateway-tester --simulate all-pass --sim-stun fail` — freeform override beats preset
7. `keeper gateway-tester --simulate ldap-cert-expiring` — LDAP warn shown with `ldap.example.com`; no `--ldap-host` required
8. `keeper gateway-tester --simulate ldap-cert-expiring --ldap-host ldap.acme.com` — user host shown
9. `keeper gateway-tester --simulate --json` — valid JSON; `passed + failed == total` per group; root contains `"simulated": true`; keys match KEY_* constants; no LDAP group (no `--ldap-host`)
9a. `keeper gateway-tester --simulate --json --ldap-host ldap.test.com` — LDAP group present in JSON with `KEY_LDAP` key
10. `keeper gateway-tester --sim-cloud fail` (no `--simulate`) — prints `Error: --sim-cloud requires --simulate`
11. `keeper gateway-tester` (real) — krelay DNS result appears first in STUN/TURN section
12. `keeper gateway-tester --timeout 2` — real run uses 2s timeout; probes time out faster on blocked ports
13. `keeper gateway-tester --simulate --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['simulated']==True"` — JSON flag present
