#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
# network_test.py — KeeperPAM gateway network readiness tester
# Tests all connectivity requirements from:
# https://docs.keeper.io/en/keeperpam/privileged-access-manager/references/gateway-network-configuration

import argparse
import asyncio
import json
import logging
import os
import socket
import ssl
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    from colorama import Fore, Style, init as colorama_init
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

from .base import Command

# ── Constants ─────────────────────────────────────────────────────────────────

# Regional TLD mapping (flag → domain suffix)
REGIONS = {
    'us':  'com',
    'eu':  'eu',
    'au':  'com.au',
    'jp':  'jp',
    'ca':  'ca',
    'gov': 'us',
}

REGION_LABELS = {
    'us':  'US',
    'eu':  'EU',
    'au':  'Australia',
    'jp':  'Japan',
    'ca':  'Canada',
    'gov': 'GovCloud',
}

# Reverse map: domain suffix → region key  e.g. 'com' → 'us'
_DOMAIN_TO_REGION = {v: k for k, v in REGIONS.items()}

# UDP ports sampled to test WebRTC media range (8 evenly-spaced across 49152–65535)
WEBRTC_SAMPLE_PORTS = [49152, 50000, 52000, 55000, 58000, 61000, 63000, 65535]

STUN_PORT = 3478
DEFAULT_TIMEOUT = 5  # seconds
BOX_WIDTH = 62       # total width of header/summary boxes


# ── Argument parser ───────────────────────────────────────────────────────────

network_test_parser = argparse.ArgumentParser(
    prog='gateway-tester',
    description='Test network connectivity requirements for KeeperPAM deployment',
)
network_test_parser.add_argument(
    '--region', dest='region',
    choices=list(REGIONS.keys()),
    default='us',
    metavar='REGION',
    help='Keeper region to test against: us, eu, au, jp, ca, gov (default: us)',
)
network_test_parser.add_argument(
    '--ldap-host', dest='ldap_host',
    metavar='HOST',
    help='LDAP server hostname to test LDAPS (port 636) connectivity',
)
network_test_parser.add_argument(
    '--ldap-port', dest='ldap_port',
    type=int,
    default=636,
    metavar='PORT',
    help='LDAPS port (default: 636)',
)
network_test_parser.add_argument(
    '--json', dest='json_output',
    action='store_true',
    help='Output results as JSON (disables color)',
)
network_test_parser.add_argument(
    '-v', '--verbose', dest='verbose',
    action='store_true',
    help='Show raw error messages',
)


# ── Result model ─────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    name: str
    passed: bool
    detail: str = ''
    warning: bool = False  # passed but needs attention


# ── Color helpers ─────────────────────────────────────────────────────────────

def _green(s):
    return f"{Fore.GREEN}{Style.BRIGHT}{s}{Style.RESET_ALL}" if HAS_COLORAMA else s

def _red(s):
    return f"{Fore.RED}{Style.BRIGHT}{s}{Style.RESET_ALL}" if HAS_COLORAMA else s

def _yellow(s):
    return f"{Fore.YELLOW}{s}{Style.RESET_ALL}" if HAS_COLORAMA else s

def _cyan(s):
    return f"{Fore.CYAN}{s}{Style.RESET_ALL}" if HAS_COLORAMA else s

def _dim(s):
    return f"{Style.DIM}{s}{Style.RESET_ALL}" if HAS_COLORAMA else s

def _bold(s):
    return f"{Style.BRIGHT}{s}{Style.RESET_ALL}" if HAS_COLORAMA else s


# ── STUN helpers ──────────────────────────────────────────────────────────────

def _build_stun_request() -> bytes:
    """Build a minimal STUN Binding Request (RFC 5389)."""
    tx_id = os.urandom(12)
    # Type=0x0001 (Binding), Length=0, Magic=0x2112A442, TxID=12 bytes
    return struct.pack('!HHI', 0x0001, 0, 0x2112A442) + tx_id


def _is_stun_success(data: bytes) -> bool:
    """Return True if data is a STUN Binding Success Response (0x0101)."""
    return len(data) >= 4 and data[0:2] == b'\x01\x01'


def _parse_stun_mapped_address(data: bytes) -> Optional[str]:
    """
    Extract the XOR-MAPPED-ADDRESS or MAPPED-ADDRESS from a STUN response.
    Returns dotted-quad IPv4 or colon-hex IPv6 string, or None.

    IPv4 XOR: 4-byte addr XOR'd with magic cookie (0x2112A442).
    IPv6 XOR: 16-byte addr XOR'd with magic cookie (4 bytes) + transaction ID
              (12 bytes from header bytes 8–19).
    """
    if len(data) < 20:
        return None
    tx_id = data[8:20]  # 12-byte transaction ID, needed for IPv6 XOR
    offset = 20         # skip 20-byte header
    while offset + 4 <= len(data):
        attr_type = struct.unpack_from('!H', data, offset)[0]
        attr_len  = struct.unpack_from('!H', data, offset + 2)[0]
        attr_val  = data[offset + 4: offset + 4 + attr_len]
        # 0x0001 = MAPPED-ADDRESS, 0x0020 = XOR-MAPPED-ADDRESS
        if attr_type in (0x0001, 0x0020) and len(attr_val) >= 4:
            family = attr_val[1]
            if family == 0x01 and len(attr_val) >= 8:   # IPv4
                addr_raw = struct.unpack_from('!I', attr_val, 4)[0]
                if attr_type == 0x0020:
                    addr_raw ^= 0x2112A442
                return socket.inet_ntoa(struct.pack('!I', addr_raw))
            elif family == 0x02 and len(attr_val) >= 20: # IPv6
                addr_bytes = bytearray(attr_val[4:20])
                if attr_type == 0x0020:
                    xor_key = struct.pack('!I', 0x2112A442) + tx_id
                    for i in range(16):
                        addr_bytes[i] ^= xor_key[i]
                return socket.inet_ntop(socket.AF_INET6, bytes(addr_bytes))
        offset += 4 + attr_len + (4 - attr_len % 4) % 4
    return None


def _stun_udp_probe(host: str, port: int, bind_port: Optional[int] = None,
                    timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, str]:
    """
    Send a STUN Binding Request to host:port over UDP.
    Tries IPv4 first, falls back to IPv6 if no IPv4 address is available.
    If bind_port is set, binds that local source port first (tests outbound firewall).
    Returns (success, detail_string).
    """
    try:
        addrs = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror:
        return False, "DNS resolution failed"

    # Build ordered list: IPv4 entries first, then IPv6
    families: List[Tuple[int, tuple]] = []
    for af in (socket.AF_INET, socket.AF_INET6):
        for res in addrs:
            if res[0] == af:
                families.append((af, res[4]))
                break  # one address per family is enough

    if not families:
        return False, "no addresses resolved"

    last_err = "no response (firewall?)"
    for af, addr in families:
        sock = socket.socket(af, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            if bind_port is not None:
                bind_host = '::' if af == socket.AF_INET6 else ''
                try:
                    sock.bind((bind_host, bind_port))
                except OSError as e:
                    last_err = f"cannot bind local port {bind_port}: {e}"
                    continue
            sock.sendto(_build_stun_request(), addr)
            data, _ = sock.recvfrom(1024)
            if _is_stun_success(data):
                ext_ip = _parse_stun_mapped_address(data)
                return True, f"external IP  {ext_ip}" if ext_ip else "binding success"
            return False, "unexpected STUN response"
        except socket.timeout:
            last_err = "no response (firewall?)"
        except OSError as e:
            last_err = str(e)
        finally:
            sock.close()

    return False, last_err


# ── Individual test functions ─────────────────────────────────────────────────

def test_dns(domain: str, verbose: bool) -> TestResult:
    name = f"DNS  keepersecurity.{domain}"
    host = f"keepersecurity.{domain}"
    try:
        results = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        if results:
            ip = results[0][4][0]
            return TestResult(name, True, f"→  {ip}")
        return TestResult(name, False, "no addresses returned")
    except socket.gaierror as e:
        return TestResult(name, False, str(e) if verbose else "DNS lookup failed")
    except Exception as e:
        return TestResult(name, False, str(e) if verbose else "resolution error")


def test_https(domain: str, verbose: bool) -> TestResult:
    name = f"HTTPS API  keepersecurity.{domain}:443"
    if not HAS_REQUESTS:
        return TestResult(name, False, "requests library not available")
    url = f"https://keepersecurity.{domain}"
    try:
        resp = _requests.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True, verify=True)
        return TestResult(name, True, f"HTTP {resp.status_code}")
    except _requests.exceptions.SSLError as e:
        detail = str(e) if verbose else "TLS error — possible corporate proxy intercept"
        return TestResult(name, False, detail)
    except _requests.exceptions.ConnectionError as e:
        detail = str(e) if verbose else "connection refused or DNS failure"
        return TestResult(name, False, detail)
    except _requests.exceptions.Timeout:
        return TestResult(name, False, "timeout (firewall?)")
    except Exception as e:
        return TestResult(name, False, str(e) if verbose else "unexpected error")


async def _ws_connect(url: str) -> Tuple[bool, str]:
    """Attempt a WebSocket connection; any server response counts as reachable."""
    try:
        async with websockets.connect(url, open_timeout=DEFAULT_TIMEOUT,
                                      close_timeout=DEFAULT_TIMEOUT) as ws:
            return True, "connected"
    except (websockets.exceptions.InvalidStatus,
            websockets.exceptions.InvalidStatusCode) as e:
        # v15+: InvalidStatus with e.response.status_code; legacy: e.status_code
        code = e.response.status_code if hasattr(e, 'response') else e.status_code
        return True, f"HTTP {code}"
    except websockets.exceptions.ConnectionClosedOK:
        return True, "connected"
    except (websockets.exceptions.WebSocketException, Exception) as e:
        msg = str(e)
        if 'timeout' in msg.lower() or 'timed out' in msg.lower():
            return False, "timeout (firewall?)"
        if 'refused' in msg.lower():
            return False, "port closed"
        if 'dns' in msg.lower() or 'nodename' in msg.lower():
            return False, "DNS resolution failed"
        # Any other exception: TCP layer worked, higher-level negotiation failed
        return True, "reachable"


def test_websocket(domain: str, verbose: bool) -> TestResult:
    name = f"WebSocket  connect.keepersecurity.{domain}:443"
    if not HAS_WEBSOCKETS:
        return TestResult(name, False, "websockets library not available")
    url = f"wss://connect.keepersecurity.{domain}/api/user/client"
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                passed, detail = pool.submit(asyncio.run, _ws_connect(url)).result()
        else:
            passed, detail = asyncio.run(_ws_connect(url))

        return TestResult(name, passed, detail)
    except Exception as e:
        return TestResult(name, False, str(e) if verbose else "connection failed")


async def _ws_connect_authenticated(url: str, params) -> Tuple[bool, str]:
    """
    Attempt an authenticated WebSocket connection using the live Commander session.
    Uses get_keeper_tokens() to build TransmissionKey + Authorization headers.
    Falls back to the unauthenticated probe if the helper is unavailable.
    """
    try:
        import base64
        from .tunnel.port_forward.tunnel_helpers import get_keeper_tokens
        encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(params)
        headers = {
            'TransmissionKey': base64.b64encode(encrypted_transmission_key).decode(),
            'Authorization': f'KeeperUser {base64.b64encode(encrypted_session_token).decode()}',
        }
        async with websockets.connect(url, additional_headers=headers,
                                      open_timeout=DEFAULT_TIMEOUT,
                                      close_timeout=DEFAULT_TIMEOUT) as ws:
            return True, "authenticated"
    except ImportError:
        # Older Commander version without tunnel helpers — fall back gracefully
        return await _ws_connect(url)
    except (websockets.exceptions.InvalidStatus,
            websockets.exceptions.InvalidStatusCode) as e:
        # Any HTTP response means the TCP+TLS stack works
        code = e.response.status_code if hasattr(e, 'response') else e.status_code
        return True, f"HTTP {code}"
    except websockets.exceptions.ConnectionClosedOK:
        return True, "authenticated"
    except (websockets.exceptions.WebSocketException, Exception) as e:
        msg = str(e)
        if 'timeout' in msg.lower() or 'timed out' in msg.lower():
            return False, "timeout (firewall?)"
        if 'refused' in msg.lower():
            return False, "port closed"
        if 'dns' in msg.lower() or 'nodename' in msg.lower():
            return False, "DNS resolution failed"
        return True, "reachable"


def test_websocket_authenticated(domain: str, params, verbose: bool) -> TestResult:
    """WebSocket test with Keeper session credentials (logged-in mode)."""
    name = f"WebSocket  connect.keepersecurity.{domain}:443"
    if not HAS_WEBSOCKETS:
        return TestResult(name, False, "websockets library not available")
    url = f"wss://connect.keepersecurity.{domain}/api/user/client"
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                passed, detail = pool.submit(
                    asyncio.run, _ws_connect_authenticated(url, params)
                ).result()
        else:
            passed, detail = asyncio.run(_ws_connect_authenticated(url, params))

        return TestResult(name, passed, detail)
    except Exception as e:
        return TestResult(name, False, str(e) if verbose else "connection failed")


def test_tcp_3478(host: str, verbose: bool) -> TestResult:
    name = f"TCP {STUN_PORT}  {host}"
    try:
        with socket.create_connection((host, STUN_PORT), timeout=DEFAULT_TIMEOUT):
            return TestResult(name, True, "port open")
    except socket.timeout:
        return TestResult(name, False, "timeout (firewall?)")
    except ConnectionRefusedError:
        return TestResult(name, False, "port closed")
    except OSError as e:
        return TestResult(name, False, str(e) if verbose else "connection error")


def test_stun_udp(host: str, verbose: bool) -> TestResult:
    name = f"UDP STUN  {host}:{STUN_PORT}"
    passed, detail = _stun_udp_probe(host, STUN_PORT)
    return TestResult(name, passed, detail)


def test_webrtc_ports(host: str, verbose: bool) -> List[TestResult]:
    results = []
    ok_count = 0
    for port in WEBRTC_SAMPLE_PORTS:
        passed, detail = _stun_udp_probe(host, STUN_PORT, bind_port=port)
        if passed:
            ok_count += 1
        elif 'bind' in detail and verbose:
            pass  # keep bind error detail
        results.append(TestResult(f"{port}", passed, ''))
    results.append(TestResult(
        f"{ok_count}/{len(WEBRTC_SAMPLE_PORTS)} sampled ports reachable",
        ok_count == len(WEBRTC_SAMPLE_PORTS),
        '',
        warning=(0 < ok_count < len(WEBRTC_SAMPLE_PORTS)),
    ))
    return results


def test_ldaps(host: str, port: int, verbose: bool) -> List[TestResult]:
    results = []

    # Step 1: TCP connectivity
    tcp_name = f"TCP {port}  {host}"
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT):
            results.append(TestResult(tcp_name, True, "port open"))
    except socket.timeout:
        results.append(TestResult(tcp_name, False, "timeout (firewall?)"))
        return results
    except ConnectionRefusedError:
        results.append(TestResult(tcp_name, False, "port closed"))
        return results
    except OSError as e:
        results.append(TestResult(tcp_name, False, str(e) if verbose else "connection error"))
        return results

    # Step 2: TLS handshake + cert inspection
    tls_name = "TLS handshake  cert valid"
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                not_after_str = cert.get('notAfter', '')
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y GMT')
                    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                    days_left = (not_after - now_utc).days
                    subject = dict(x[0] for x in cert.get('subject', []))
                    cn = subject.get('commonName', host)
                    if days_left < 0:
                        results.append(TestResult(
                            tls_name, False,
                            f"EXPIRED {abs(days_left)} days ago  CN={cn}"
                        ))
                    elif days_left < 30:
                        results.append(TestResult(
                            tls_name, True,
                            f"expires {not_after.strftime('%Y-%m-%d')}  ({days_left} days)  rotation recommended",
                            warning=True,
                        ))
                    else:
                        results.append(TestResult(
                            tls_name, True,
                            f"expires {not_after.strftime('%Y-%m-%d')}  ({days_left} days)  CN={cn}"
                        ))
                else:
                    results.append(TestResult(tls_name, True, "handshake OK"))
    except ssl.SSLCertVerificationError as e:
        results.append(TestResult(tls_name, False,
                                  str(e) if verbose else "certificate verification failed"))
    except ssl.SSLError as e:
        results.append(TestResult(tls_name, False, str(e) if verbose else "TLS error"))
    except socket.timeout:
        results.append(TestResult(tls_name, False, "TLS handshake timeout"))
    except Exception as e:
        results.append(TestResult(tls_name, False, str(e) if verbose else "unexpected error"))

    return results


# ── Terminal rendering ────────────────────────────────────────────────────────

def _flush(text: str = '') -> None:
    print(text, flush=True)


def _print_banner(domain: str, region: str, ctx: dict) -> None:
    """Print the header box and session metadata."""
    if HAS_COLORAMA:
        colorama_init()

    inner = BOX_WIDTH - 2
    title = "KeeperPAM  ·  Gateway Network Readiness Tester"
    _flush(_cyan("╔" + "═" * inner + "╗"))
    _flush(_cyan("║") + _bold(title.center(inner)) + _cyan("║"))
    _flush(_cyan("╚" + "═" * inner + "╝"))

    if ctx.get('logged_in'):
        _flush(f"  Vault    {ctx['vault_user']}")
        region_str = f"{REGION_LABELS[region]} (auto-detected)  ·  keepersecurity.{domain}"
    else:
        region_str = f"{REGION_LABELS[region]}  ·  keepersecurity.{domain}"
        _flush(_dim("  Tip: run 'keeper login' first to auto-detect region and LDAP"))

    _flush(f"  Region   {region_str}")
    if ctx.get('ldap_source'):
        _flush(_dim(f"  LDAP     auto-detected from {ctx['ldap_source']}"))
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d  %H:%M UTC')
    _flush(f"  Date     {now}")


def _print_section(title: str) -> None:
    _flush(f"\n  {_cyan('▸')}  {_bold(title)}")
    _flush(f"  {_dim('─' * (BOX_WIDTH - 2))}")


def _icon(r: TestResult) -> str:
    if r.warning:
        return _yellow("⚠")
    return _green("✓") if r.passed else _red("✗")


def _print_result(r: TestResult) -> None:
    line = f"    {_icon(r)}  {r.name}"
    if r.detail:
        line += f"  {_dim('·')}  {_dim(r.detail)}"
    _flush(line)


def _print_webrtc_results(results: List[TestResult]) -> None:
    """Print port results compactly on one line, then the summary."""
    port_results = [r for r in results if 'sampled' not in r.name]
    summary = next((r for r in results if 'sampled' in r.name), None)

    parts = [f"{_icon(r)} {r.name}" for r in port_results]
    _flush("    " + "   ".join(parts))

    if summary:
        label = summary.name
        if summary.warning:
            _flush(f"    {_yellow('⚠')}  {label}")
        elif summary.passed:
            _flush(f"    {_green('✓')}  {label}")
        else:
            _flush(f"    {_red('✗')}  {label}")


def _print_summary(total_passed: int, total_checks: int, total_warnings: int) -> None:
    inner = BOX_WIDTH - 2
    all_pass = total_passed == total_checks
    none_pass = total_passed == 0

    if all_pass:
        status = "✓  GATEWAY READY"
        color = _green
    elif none_pass:
        status = "✗  GATEWAY BLOCKED"
        color = _red
    else:
        status = "⚠  GATEWAY PARTIAL"
        color = _yellow

    checks_str = f"{total_passed} / {total_checks} checks passed"
    if total_warnings:
        checks_str += f"  ·  {total_warnings} warning{'s' if total_warnings != 1 else ''}"

    summary_text = f"{status}  ·  {checks_str}"
    padded = f"  {summary_text}  "

    _flush()
    _flush(color("  " + "═" * inner))
    _flush("  " + color(padded.ljust(inner)))
    _flush(color("  " + "═" * inner))
    _flush()


# ── JSON rendering ────────────────────────────────────────────────────────────

def render_json(
    domain: str,
    region: str,
    groups: dict,
    total_passed: int,
    total_checks: int,
    total_warnings: int,
    ctx: Optional[dict] = None,
) -> None:
    ctx = ctx or {}
    out = {
        "region": region,
        "domain": f"keepersecurity.{domain}",
        "vault_user": ctx.get('vault_user'),
        "auto_detected": ctx.get('logged_in', False),
        "summary": {
            "total": total_checks,
            "passed": total_passed,
            "failed": total_checks - total_passed,
            "warnings": total_warnings,
        },
        "groups": {},
    }
    for section_title, results in groups.items():
        out["groups"][section_title] = [
            {"name": r.name, "passed": r.passed, "warning": r.warning, "detail": r.detail}
            for r in results
        ]
    print(json.dumps(out, indent=2))


# ── Session auto-detection helpers ───────────────────────────────────────────

def _detect_region_from_params(params) -> Optional[str]:
    """
    Extract the region key from the logged-in Commander session.
    Parses params.rest_context.server_base (e.g. 'https://keepersecurity.eu/api/rest/').
    Returns a REGIONS key ('us', 'eu', etc.) or None.
    """
    try:
        server = params.rest_context.server_base or ''
        host = (urlsplit(server).hostname or '').lower()
        dot = host.find('.')
        if dot < 0:
            return None
        suffix = host[dot + 1:]   # 'com', 'eu', 'com.au', 'jp', 'ca', 'us'
        return _DOMAIN_TO_REGION.get(suffix)
    except Exception:
        return None


def _find_ldap_from_pam_configs(params) -> Optional[Tuple[str, int]]:
    """
    Scan PAM Configuration records (version-6 vault records) for an LDAP host field.
    Returns (hostname, port) for the first match, or None.
    """
    try:
        from .pam.config_helper import pam_configurations_get_all, pam_decrypt_configuration_data
    except ImportError:
        return None

    try:
        configs = pam_configurations_get_all(params)
    except Exception:
        return None

    for config in configs:
        try:
            data = pam_decrypt_configuration_data(config)
            for fld in data.get('fields', []):
                label = (fld.get('label') or '').lower()
                ftype = (fld.get('type') or '').lower()
                values = fld.get('value') or []
                if not values:
                    continue
                if ftype == 'host' or 'ldap' in label:
                    v = values[0]
                    if isinstance(v, dict) and v.get('hostName'):
                        port = v.get('port', 636)
                        return v['hostName'], int(port) if port else 636
        except Exception as e:
            logging.debug('gateway-tester: failed to read PAM config: %s', e)
            continue

    return None


# ── Commander Command class ───────────────────────────────────────────────────

class NetworkTestCommand(Command):
    def get_parser(self):
        return network_test_parser

    def is_authorised(self):
        # Runs with or without login; session enhances auto-detection only
        return False

    def execute(self, params, **kwargs):
        region      = kwargs.get('region', 'us')
        ldap_host   = kwargs.get('ldap_host')
        ldap_port   = kwargs.get('ldap_port', 636)
        json_output = kwargs.get('json_output', False)
        verbose     = kwargs.get('verbose', False)

        # ── Auto-detect from Commander session if logged in ───────────────────
        logged_in  = bool(params and getattr(params, 'session_token', None))
        vault_user = getattr(params, 'user', None) if logged_in else None
        ldap_source = None

        if logged_in:
            detected = _detect_region_from_params(params)
            if detected:
                region = detected
            if not ldap_host:
                result = _find_ldap_from_pam_configs(params)
                if result:
                    ldap_host, ldap_port = result
                    ldap_source = 'PAM config'

        domain = REGIONS.get(region, 'com')
        krelay = f"krelay.keepersecurity.{domain}"
        ctx = {'logged_in': logged_in, 'vault_user': vault_user, 'ldap_source': ldap_source}

        # ── JSON mode: batch all tests then render ────────────────────────────
        if json_output:
            groups = {}
            ws_test = (test_websocket_authenticated(domain, params, verbose)
                       if logged_in else test_websocket(domain, verbose))
            groups["DNS & Cloud Connectivity"] = [
                test_dns(domain, verbose),
                test_https(domain, verbose),
                ws_test,
            ]
            groups[f"STUN / TURN  ({krelay})"] = [
                test_tcp_3478(krelay, verbose),
                test_stun_udp(krelay, verbose),
            ]
            groups["WebRTC Media Ports  (UDP 49152\u201365535)"] = \
                test_webrtc_ports(krelay, verbose)
            if ldap_host:
                groups[f"LDAPS  ({ldap_host}:{ldap_port})"] = \
                    test_ldaps(ldap_host, ldap_port, verbose)

            all_results = [r for g in groups.values() for r in g]
            countable = [r for r in all_results if 'sampled' not in r.name]
            render_json(domain, region, groups,
                        sum(1 for r in countable if r.passed),
                        len(countable),
                        sum(1 for r in countable if r.warning),
                        ctx)
            return

        # ── Terminal mode: stream output section by section ───────────────────
        _print_banner(domain, region, ctx)
        groups = {}
        countable = []

        # Group 1: DNS & Cloud Connectivity
        title = "DNS & Cloud Connectivity"
        _print_section(title)
        ws_test = (test_websocket_authenticated(domain, params, verbose)
                   if logged_in else test_websocket(domain, verbose))
        g1 = [test_dns(domain, verbose),
              test_https(domain, verbose),
              ws_test]
        groups[title] = g1
        for r in g1:
            _print_result(r)
            countable.append(r)

        # Group 2: STUN / TURN
        title = f"STUN / TURN  ·  {krelay}"
        _print_section(title)
        g2 = [test_tcp_3478(krelay, verbose), test_stun_udp(krelay, verbose)]
        groups[title] = g2
        for r in g2:
            _print_result(r)
            countable.append(r)

        # Group 3: WebRTC media ports
        title = "WebRTC Media Ports  ·  UDP 49152\u201365535"
        _print_section(title)
        g3 = test_webrtc_ports(krelay, verbose)
        groups[title] = g3
        _print_webrtc_results(g3)
        countable.extend(r for r in g3 if 'sampled' not in r.name)

        # Group 4 (optional): LDAPS
        if ldap_host:
            title = f"LDAPS  ·  {ldap_host}:{ldap_port}"
            _print_section(title)
            g4 = test_ldaps(ldap_host, ldap_port, verbose)
            groups[title] = g4
            for r in g4:
                _print_result(r)
                countable.append(r)

        _print_summary(
            sum(1 for r in countable if r.passed),
            len(countable),
            sum(1 for r in countable if r.warning),
        )
