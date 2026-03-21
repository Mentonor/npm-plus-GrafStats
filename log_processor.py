#!/usr/bin/python3
"""Unified log processor for NPMplus/NginxProxyManager.

Replaces sendips.sh, sendredirectionips.sh, Getipinfo.py, and Internalipinfo.py
with a single efficient Python service that:
  - Reads all log files in one process (no per-line Python spawning)
  - Caches GeoIP lookups in memory (databases opened once at startup)
  - Keeps AbuseIPDB results in memory (backed by the existing JSON file)
  - Reuses a single InfluxDB client connection across all writes
  - Uses Python ipaddress module instead of the grepcidr binary
  - Supports REDIRECTION_LOGS=TRUE/ONLY configurations
  - Optionally batches InfluxDB writes (BATCH_SIZE env var, default 1)
"""

import os
import sys
import re
import time
import json
import fcntl
import glob
import fnmatch
import signal
import ipaddress
import threading
from datetime import datetime, timezone

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import geoip2.database
import geoip2.errors
import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS
from ua_parser import user_agent_parser

try:
    import requests as _requests_module
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
DATA_DIR = "/data"
CACHE_FILE = os.path.join(DATA_DIR, "abuseip_cache.json")
CACHE_EXPIRATION_HOURS = 48
INFLUX_TOKEN_FILE = os.path.join(DATA_DIR, "influxdb-token.txt")
ABUSEIP_KEY_FILE = os.path.join(DATA_DIR, "abuseipdb-key.txt")
MONITOR_FILE_PATH = os.path.join(DATA_DIR, "monitoringips.txt")
WHITELIST_FILE_PATH = os.path.join(DATA_DIR, "whitelist_ips.txt")
GEOIP_CITY_DB = "/geolite/GeoLite2-City.mmdb"
GEOIP_ASN_DB = "/geolite/GeoLite2-ASN.mmdb"

# ---------------------------------------------------------------------------
# Tail and health-check configuration
# ---------------------------------------------------------------------------
TAIL_NO_DATA_REOPEN_S: int   = 60    # reopen file when no new data arrives for this many seconds
TAIL_ROTATION_CHECK_S: float = 5.0   # check for file rotation every N seconds
TAIL_SLEEP_S: float          = 0.05  # sleep between readline() attempts

HEALTH_CHECK_INTERVAL_S: int = 60    # run the health-check sweep every N seconds

# ---------------------------------------------------------------------------
# InfluxDB retry configuration
# ---------------------------------------------------------------------------
INFLUX_MAX_RETRIES: int    = 5    # maximum write retry attempts
INFLUX_RETRY_BASE_S: float = 1.0  # initial backoff; doubles on each subsequent retry

# ---------------------------------------------------------------------------
# Compiled regular expressions (built once, reused for every log line)
# ---------------------------------------------------------------------------

# Matches IPv4 addresses
_IPV4_RE = re.compile(
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
)

# Matches IPv6 addresses (full, compressed, and IPv4-mapped forms).
# Alternatives are ordered longest/most-specific first so the regex engine
# does not stop at a trailing '::' before consuming the remaining hex groups.
_IPV6_RE = re.compile(
    r'(?:'
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'                              # 1:2:3:4:5:6:7:8
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'                         # 1::8  through  1:2:3:4:5:6::8
    r'|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}'               # 1::7:8
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}'               # 1::6:7:8
    r'|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}'               # 1::5:6:7:8
    r'|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}'               # 1::4:5:6:7:8
    r'|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}'                         # 1::3:4:5:6:7:8
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'                                           # ::2:3:4:5:6:7:8
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'                                           # 1::  through  1:2:3:4:5:6:7::
    r'|::'                                                                     # ::
    r'|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+'                        # fe80::...%eth0
    r'|::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'   # ::ffff:1.2.3.4
      r'(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' # 1:2:3:4::1.2.3.4
      r'(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    r')'
)

# Matches a log line that contains at least one IPv4 or IPv6 address
_HAS_IP_RE = re.compile(
    r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'           # IPv4
    r'|(?:[0-9a-fA-F]{1,4}:){2}[0-9a-fA-F:]+'  # IPv6 (coarse check)
)

# Extracts the first domain-like token from a line
# Note: original bash uses {1,3}? where ? makes the group optional (0-3 prefix labels)
_DOMAIN_RE = re.compile(
    r'(?:[a-z0-9\-]*\.){0,3}[a-z0-9\-]*\.[A-Za-z]{2,6}'
)

# Extracts User-Agent from the NPMplus log field "[Sent-to <host>] "<ua>""
_UA_RE = re.compile(r'\[Sent-to [^\]]+\] "([^"]*)"')

# Extracts the forwarded-to host from "[Sent-to <ip>:<port>]"
_SENT_TO_RE = re.compile(r'\[Sent-to ([^\]:]+)(?::\d+)?\]')

# ---------------------------------------------------------------------------
# Strict NPMplus log-line schema validators
# ---------------------------------------------------------------------------

# Proxy log format:
#   [DD/Mon/YYYY:HH:MM:SS +TTTT] proxy-domain client-ip session-time "request" statuscode response-size bytes [referer [ua]]
# Groups: (1) client-ip  (2) statuscode  (3) response-size  (4) bytes
_PROXY_LOG_SCHEMA_RE = re.compile(
    r'^\['
    r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}'  # timestamp
    r'\]\s+'
    r'\S+\s+'           # proxy-domain (may include /proxy-ip suffix)
    r'(\S+)\s+'         # group 1: client-ip (IPv4 or IPv6)
    r'\S+\s+'           # session-time
    r'"[^"]*"\s+'       # quoted request line
    r'(\d{3})\s+'       # group 2: HTTP status code
    r'(\d+)\s+'         # group 3: response-size
    r'(\d+)'            # group 4: bytes transferred
)

# Redirection log format:
#   [DD/Mon/YYYY:HH:MM:SS +TTTT] statuscode client-ip [...]
# Groups: (1) statuscode  (2) client-ip
_REDIRECT_LOG_SCHEMA_RE = re.compile(
    r'^\['
    r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}'  # timestamp
    r'\]\s+'
    r'(\d{3})\s+'       # group 1: HTTP status code
    r'(\S+)'            # group 2: client-ip (IPv4 or IPv6)
)

# Month abbreviation -> zero-padded number
_MONTH_MAP = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12',
}

# ---------------------------------------------------------------------------
# Global shared state (initialised once in main(), read-only thereafter
# except for the AbuseIPDB in-memory cache)
# ---------------------------------------------------------------------------
_city_reader = None       # geoip2 city DB reader
_asn_reader = None        # geoip2 ASN DB reader
_has_asn_db = False

_abuseip_cache: dict = {}       # { ip: {'timestamp': float, 'data': dict} }
_abuseip_cache_lock = threading.Lock()
_abuseip_key: str | None = None

_external_ip: str | None = None
_monitor_networks: list = []  # list of ipaddress.ip_network objects
_whitelist_networks: list = []  # list of ipaddress.ip_network objects

_influx_client = None
_write_api = None
_influx_bucket: str = ""
_influx_org: str = ""

_batch_size: int = 1          # set from env BATCH_SIZE
_batch: list = []
_batch_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Shutdown coordination & active tail tracking
# ---------------------------------------------------------------------------

# Set by signal handlers; all long-running loops poll this event.
_shutdown_event = threading.Event()

# Maps filepath -> Thread for all currently running tail threads.
_active_tails: dict = {}
_active_tails_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Debug mode and statistics
# ---------------------------------------------------------------------------

_debug_mode: bool = False   # enabled via --debug CLI arg or DEBUG=true env var

_stats: dict = {
    'total_sent': 0,            # total points successfully written to InfluxDB
    'total_errors': 0,          # total failed InfluxDB writes
    'send_timestamps': [],      # monotonic timestamps of every successful write
    'last_db_response_ms': None,  # last round-trip latency in milliseconds
    'daily_abuseip_checks': 0,  # AbuseIPDB API calls made today
    'daily_whitelist_hits': 0,  # IPs matched against whitelist today
    'daily_reset_date': datetime.now().strftime('%Y-%m-%d'),  # date of last daily counter reset
}
_stats_lock = threading.Lock()

STATS_INTERVAL_S: int = 30   # how often (seconds) to print the summary line
_last_stats_time: float = 0.0  # monotonic timestamp of last stats print


def _debug_print(*args, **kwargs) -> None:
    """Print only when debug mode is active."""
    if _debug_mode:
        print(*args, **kwargs)


def _signal_handler(signum, frame) -> None:
    """Handle SIGTERM / SIGINT by setting the global shutdown event."""
    sig_name = signal.Signals(signum).name
    print(f"\n[shutdown] Received {sig_name}, initiating graceful shutdown...")
    _shutdown_event.set()


def _print_stats() -> None:
    """Print a one-line statistics summary to stdout."""
    now = time.monotonic()
    five_min_ago = now - 300
    one_hour_ago = now - 3600
    today_str = datetime.now().strftime('%Y-%m-%d')

    with _stats_lock:
        total  = _stats['total_sent']
        errors = _stats['total_errors']
        last_db = _stats['last_db_response_ms']

        # Reset daily counters when the date changes
        if _stats['daily_reset_date'] != today_str:
            _stats['daily_abuseip_checks'] = 0
            _stats['daily_whitelist_hits'] = 0
            _stats['daily_reset_date'] = today_str

        daily_abuseip = _stats['daily_abuseip_checks']
        daily_whitelist = _stats['daily_whitelist_hits']

        # Trim timestamps older than 1 hour to avoid unbounded growth
        _stats['send_timestamps'] = [
            ts for ts in _stats['send_timestamps'] if ts >= one_hour_ago
        ]
        last_5min = sum(1 for ts in _stats['send_timestamps'] if ts >= five_min_ago)
        last_hour = len(_stats['send_timestamps'])

    db_str = f"{last_db:.1f} ms" if last_db is not None else "N/A"
    print(
        f"[stats] total={total} | last_hour={last_hour} | last_5min={last_5min}"
        f" | errors={errors} | last_db_latency={db_str}"
        f" | daily_abuseip_checks={daily_abuseip} | daily_whitelist_hits={daily_whitelist}"
    )


# ---------------------------------------------------------------------------
# Initialisation helpers
# ---------------------------------------------------------------------------

def _init_geoip() -> None:
    global _city_reader, _asn_reader, _has_asn_db
    if os.path.exists(GEOIP_CITY_DB):
        _city_reader = geoip2.database.Reader(GEOIP_CITY_DB)
        print(f"GeoIP City DB loaded: {GEOIP_CITY_DB}")
    else:
        print(f"WARNING: GeoIP City DB not found at {GEOIP_CITY_DB}")
    if os.path.exists(GEOIP_ASN_DB):
        _asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
        _has_asn_db = True
        print(f"GeoIP ASN DB loaded: {GEOIP_ASN_DB}")


def _init_abuseip() -> None:
    global _abuseip_key, _abuseip_cache
    if os.path.exists(ABUSEIP_KEY_FILE):
        with open(ABUSEIP_KEY_FILE, 'r') as f:
            _abuseip_key = f.read().strip() or None
    if _abuseip_key is None:
        _abuseip_key = os.getenv('ABUSEIP_KEY') or None

    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                _abuseip_cache = json.load(f)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            print(f"AbuseIPDB cache loaded: {len(_abuseip_cache)} entries.")
        except (json.JSONDecodeError, IOError, OSError) as exc:
            print(f"Could not load AbuseIPDB cache ({exc}). Starting fresh.")
            _abuseip_cache = {}


def _init_influx() -> None:
    global _influx_client, _write_api, _influx_bucket, _influx_org
    ifhost = os.getenv('INFLUX_HOST', '')
    _influx_org = os.getenv('INFLUX_ORG', '')
    _influx_bucket = os.getenv('INFLUX_BUCKET', '')

    iftoken = os.getenv('INFLUX_TOKEN')
    if not iftoken and os.path.exists(INFLUX_TOKEN_FILE):
        with open(INFLUX_TOKEN_FILE, 'r') as f:
            iftoken = f.read().strip()
    if not iftoken:
        print("ERROR: No InfluxDB token found. Exiting.")
        sys.exit(1)

    _influx_client = influxdb_client.InfluxDBClient(
        url=ifhost, token=iftoken, org=_influx_org
    )
    _write_api = _influx_client.write_api(write_options=SYNCHRONOUS)
    print(f"InfluxDB client initialised (host={ifhost}, org={_influx_org}).")


def _init_external_ip() -> None:
    global _external_ip
    if not _HAS_REQUESTS:
        print("requests module not available; external IP detection skipped.")
        return
    try:
        resp = _requests_module.get('https://ifconfig.me/ip', timeout=10)
        _external_ip = resp.text.strip()
        print(f"External IP: {_external_ip}")
    except Exception as exc:
        print(f"Could not fetch external IP ({exc}). External-IP filtering disabled.")
        _external_ip = None


def _init_monitor_ips() -> None:
    global _monitor_networks
    if not os.path.exists(MONITOR_FILE_PATH):
        return
    networks = []
    try:
        with open(MONITOR_FILE_PATH, 'r') as f:
            for raw in f:
                entry = raw.strip()
                if not entry or entry.startswith('#'):
                    continue
                try:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    print(f"Skipping invalid monitor entry: {entry!r}")
        _monitor_networks = networks
        print(f"Monitor IPs loaded: {len(_monitor_networks)} network(s).")
    except IOError as exc:
        print(f"Could not load monitor IPs ({exc}).")


def _init_whitelist_ips() -> None:
    global _whitelist_networks
    networks = []

    if os.path.exists(WHITELIST_FILE_PATH):
        try:
            with open(WHITELIST_FILE_PATH, 'r') as f:
                for raw in f:
                    entry = raw.strip()
                    if not entry or entry.startswith('#'):
                        continue
                    try:
                        networks.append(ipaddress.ip_network(entry, strict=False))
                    except ValueError:
                        print(f"Skipping invalid whitelist entry: {entry!r}")
        except IOError as exc:
            print(f"Could not load whitelist IPs from file ({exc}).")

    env_val = os.getenv('WHITELIST_IPS', '')
    for entry in re.split(r'[,\n]+', env_val):
        entry = entry.strip()
        if not entry or entry.startswith('#'):
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            print(f"Skipping invalid WHITELIST_IPS entry: {entry!r}")

    _whitelist_networks = networks
    if _whitelist_networks:
        print(f"Whitelist IPs loaded: {len(_whitelist_networks)} network(s).")


# ---------------------------------------------------------------------------
# Log-line parsing helpers
# ---------------------------------------------------------------------------

def _parse_timestamp(line: str) -> str | None:
    """Convert the NPMplus log timestamp to RFC 3339 for InfluxDB.

    Log format: [30/May/2023:14:16:48 +0000] ...
    Bash equivalent: measurementtime="${line:1:26}"
    """
    try:
        # line[0] == '['; line[1:27] == "30/May/2023:14:16:48 +0000"
        raw = line[1:27]
        month = _MONTH_MAP.get(raw[3:6])
        if month is None:
            return None
        # "30/May/2023:14:16:48 +0000"
        #  0123456789012345678901234 5
        day   = raw[0:2]    # "30"
        year  = raw[7:11]   # "2023"
        hms   = raw[12:20]  # "14:16:48"
        tz    = raw[21:24] + ':' + raw[24:26]  # "+00:00"
        return f"{year}-{month}-{day}T{hms}{tz}"
    except Exception:
        return None


def _extract_ips(line: str) -> list[str]:
    """Return all IPv4 and IPv6 addresses found in *line*."""
    return _IPV4_RE.findall(line) + _IPV6_RE.findall(line)


def _extract_domain(line: str) -> str:
    """Return the first domain-like token in *line*."""
    m = _DOMAIN_RE.search(line)
    return m.group(0) if m else ''


def _extract_useragent(line: str) -> str:
    """Return the User-Agent from the NPMplus '[Sent-to …] "<ua>"' field."""
    m = _UA_RE.search(line)
    return m.group(1) if m else '-'


def _extract_target_ip(line: str) -> str:
    """Return the forwarded-to IP from '[Sent-to <ip>:<port>]'."""
    m = _SENT_TO_RE.search(line)
    return m.group(1) if m else ''


def _parse_proxy_line(line: str) -> dict | None:
    """Parse a proxy-host access log line using strict schema validation.

    Expected NPMplus format:
      [DD/Mon/YYYY:HH:MM:SS +TTTT] proxy-domain client-ip session-time "request" statuscode response-size bytes [referer [ua]]

    The client IP is extracted from its fixed position (field 3 after the timestamp)
    and validated via the ipaddress module, supporting both IPv4 and IPv6.
    Malformed lines are logged and skipped.
    """
    ts = _parse_timestamp(line)
    if ts is None:
        _debug_print(f"Malformed proxy log (invalid timestamp): {line!r}")
        return None

    m = _PROXY_LOG_SCHEMA_RE.match(line)
    if m is None:
        _debug_print(f"Malformed proxy log (schema mismatch): {line!r}")
        return None

    outside_ip_raw = m.group(1)
    try:
        outside_ip = str(ipaddress.ip_address(outside_ip_raw))  # validated & normalised
    except ValueError:
        _debug_print(f"Malformed proxy log (invalid client IP {outside_ip_raw!r}): {line!r}")
        return None

    try:
        statuscode = int(m.group(2))
    except (IndexError, ValueError):
        statuscode = 0

    try:
        length = int(m.group(4))    # bytes transferred
    except (IndexError, ValueError):
        length = 0

    target_ip = _extract_target_ip(line) or outside_ip

    return {
        'timestamp':  ts,
        'outside_ip': outside_ip,
        'target_ip':  target_ip or '',
        'domain':     _extract_domain(line),
        'statuscode': statuscode,
        'length':     length,
        'useragent':  _extract_useragent(line),
        'log_type':   'proxy',
    }


def _parse_redirection_line(line: str) -> dict | None:
    """Parse a redirection-host access log line using strict schema validation.

    Expected format:
      [DD/Mon/YYYY:HH:MM:SS +TTTT] statuscode client-ip [...]

    The client IP is extracted from its fixed position and validated via the
    ipaddress module, supporting both IPv4 and IPv6.
    Malformed lines are logged and skipped.
    """
    ts = _parse_timestamp(line)
    if ts is None:
        _debug_print(f"Malformed redirection log (invalid timestamp): {line!r}")
        return None

    m = _REDIRECT_LOG_SCHEMA_RE.match(line)
    if m is None:
        _debug_print(f"Malformed redirection log (schema mismatch): {line!r}")
        return None

    try:
        statuscode = int(m.group(1))
    except (IndexError, ValueError):
        statuscode = 0

    outside_ip_raw = m.group(2)
    try:
        outside_ip = str(ipaddress.ip_address(outside_ip_raw))  # validated & normalised
    except ValueError:
        _debug_print(f"Malformed redirection log (invalid client IP {outside_ip_raw!r}): {line!r}")
        return None

    return {
        'timestamp':  ts,
        'outside_ip': outside_ip,
        'target_ip':  'redirect',
        'domain':     _extract_domain(line),
        'statuscode': statuscode,
        'length':     0,
        'useragent':  _extract_useragent(line),
        'log_type':   'redirection',
    }


# ---------------------------------------------------------------------------
# GeoIP lookup (in-memory, no per-call open/close)
# ---------------------------------------------------------------------------

def _geoip_lookup(ip: str) -> dict:
    """Return a dict of geo fields for *ip*; empty dict on failure."""
    if _city_reader is None:
        return {}
    try:
        r = _city_reader.city(ip)
        info: dict = {
            'lat':     r.location.latitude,
            'lon':     r.location.longitude,
            'iso':     r.country.iso_code or '',
            'state':   r.subdivisions.most_specific.name or '',
            'city':    r.city.name or '',
            'country': r.country.name or '',
            'zip':     r.postal.code or '',
        }
        if _has_asn_db and _asn_reader:
            try:
                asn_r = _asn_reader.asn(ip)
                info['asn'] = asn_r.autonomous_system_organization or 'Unknown'
            except geoip2.errors.AddressNotFoundError:
                info['asn'] = 'No ASN associated'
            except Exception as exc:
                info['asn'] = f'Error: {exc}'
        return info
    except geoip2.errors.AddressNotFoundError:
        return {}
    except Exception as exc:
        print(f"GeoIP lookup error for {ip}: {exc}")
        return {}


# ---------------------------------------------------------------------------
# AbuseIPDB lookup (in-memory cache, disk persistence)
# ---------------------------------------------------------------------------

def _abuseip_lookup(ip: str) -> dict | None:
    """Return AbuseIPDB data for *ip* (uses in-memory cache)."""
    if not _abuseip_key or not _HAS_REQUESTS:
        return None
    now = time.time()
    with _abuseip_cache_lock:
        entry = _abuseip_cache.get(ip)
        if entry and now - entry.get('timestamp', 0) < CACHE_EXPIRATION_HOURS * 3600:
            _debug_print(f"AbuseIPDB cache HIT: {ip}")
            return entry['data']

    _debug_print(f"AbuseIPDB cache MISS: {ip}")
    with _stats_lock:
        _stats['daily_abuseip_checks'] += 1
    try:
        resp = _requests_module.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Accept': 'application/json', 'Key': _abuseip_key},
            params={'ipAddress': ip, 'maxAgeInDays': '90'},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get('data')
        if data:
            with _abuseip_cache_lock:
                _abuseip_cache[ip] = {'timestamp': now, 'data': data}
                _persist_abuseip_cache()
        return data
    except Exception as exc:
        print(f"AbuseIPDB API error for {ip}: {exc}")
        return None


def _persist_abuseip_cache() -> None:
    """Write the in-memory AbuseIPDB cache to disk (must hold _abuseip_cache_lock)."""
    try:
        with open(CACHE_FILE, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(_abuseip_cache, f, indent=4)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except (IOError, OSError) as exc:
        print(f"Error persisting AbuseIPDB cache: {exc}")


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------

def _is_internal(ip: str) -> bool:
    """Return True if *ip* is a private, loopback, or link-local address (IPv4 or IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _is_external_own(ip: str) -> bool:
    return _external_ip is not None and ip == _external_ip


def _is_monitor(ip: str) -> bool:
    if not _monitor_networks:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _monitor_networks)
    except ValueError:
        return False


def _is_whitelisted(ip: str) -> bool:
    if not _whitelist_networks:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _whitelist_networks)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# InfluxDB point construction & writing
# ---------------------------------------------------------------------------

def _parse_ua(useragent: str) -> tuple[str, str, str]:
    parsed = user_agent_parser.Parse(useragent)
    browser = parsed['user_agent']['family'] or 'Unknown'
    major   = parsed['user_agent']['major'] or '0'
    version = f"{browser}: {major}"
    if parsed['user_agent']['minor']:
        version += '.' + parsed['user_agent']['minor']
    os_fam = parsed['os']['family'] or 'Unknown'
    return browser, version, os_fam


def _build_point(data: dict, measurement: str, with_geo: bool) -> influxdb_client.Point:
    ip        = data['outside_ip']
    domain    = data['domain']
    target    = data['target_ip']
    status    = data['statuscode']
    length    = data['length']
    useragent = data['useragent']

    browser, browser_version, os_family = _parse_ua(useragent)

    point = influxdb_client.Point(measurement)
    point.tag("IP",     ip)
    point.tag("Domain", domain)
    point.tag("Target", target)

    point.field("IP",              ip)
    point.field("Domain",          domain)
    point.field("Target",          target)
    point.field("browser",         browser)
    point.field("browser_version", browser_version)
    point.field("os",              os_family)
    point.field("length",          length)
    point.field("statuscode",      status)
    point.field("metric",          1)

    if with_geo and ip:
        geo = _geoip_lookup(ip)
        if geo:
            point.tag("key",       geo.get('iso', ''))
            point.tag("latitude",  str(geo.get('lat', '')))
            point.tag("longitude", str(geo.get('lon', '')))
            point.tag("City",      geo.get('city', ''))
            point.tag("State",     geo.get('state', ''))
            point.tag("Name",      geo.get('country', ''))

            point.field("key",       geo.get('iso', ''))
            point.field("latitude",  geo.get('lat') or 0.0)
            point.field("longitude", geo.get('lon') or 0.0)
            point.field("State",     geo.get('state', ''))
            point.field("City",      geo.get('city', ''))
            point.field("Name",      geo.get('country', ''))

            if _has_asn_db and 'asn' in geo:
                point.tag("Asn",   geo['asn'])
                point.field("Asn", geo['asn'])

        if _abuseip_key and ip:
            abuse = _abuseip_lookup(ip)
            if abuse:
                score   = str(abuse.get('abuseConfidenceScore', 0))
                reports = str(abuse.get('totalReports', 0))
                point.tag("abuseConfidenceScore",   score)
                point.tag("totalReports",           reports)
                point.field("abuseConfidenceScore", score)
                point.field("totalReports",         reports)

    if data['timestamp']:
        point.time(data['timestamp'])

    return point


def _flush_batch(points: list) -> None:
    """Write a list of points to InfluxDB with exponential-backoff retry."""
    if not points:
        return
    for attempt in range(INFLUX_MAX_RETRIES):
        t_start = time.monotonic()
        try:
            _write_api.write(bucket=_influx_bucket, org=_influx_org, record=points)
            t_end = time.monotonic()
            elapsed_ms = (t_end - t_start) * 1000
            with _stats_lock:
                _stats['total_sent'] += len(points)
                _stats['last_db_response_ms'] = elapsed_ms
                _stats['send_timestamps'].extend([t_end] * len(points))
            _debug_print(f"Wrote {len(points)} point(s) to InfluxDB.")
            return
        except Exception as exc:
            ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            print(f"[{ts}] InfluxDB write error (attempt {attempt + 1}/{INFLUX_MAX_RETRIES}): {exc}")
            if attempt < INFLUX_MAX_RETRIES - 1 and not _shutdown_event.is_set():
                wait_s = INFLUX_RETRY_BASE_S * (2 ** attempt)
                print(f"[{ts}] Retrying in {wait_s:.1f}s…")
                _shutdown_event.wait(timeout=wait_s)
    # All retries exhausted
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f"[{ts}] InfluxDB write failed after {INFLUX_MAX_RETRIES} attempts – {len(points)} point(s) lost.")
    with _stats_lock:
        _stats['total_errors'] += len(points)


def _send(data: dict, measurement: str, with_geo: bool) -> None:
    """Build an InfluxDB point and either queue it (batching) or write immediately."""
    point = _build_point(data, measurement, with_geo)
    if _batch_size <= 1:
        _flush_batch([point])
        return
    to_flush: list = []
    with _batch_lock:
        _batch.append(point)
        if len(_batch) >= _batch_size:
            to_flush = _batch.copy()
            _batch.clear()
    if to_flush:
        _flush_batch(to_flush)


# ---------------------------------------------------------------------------
# Log-line routing (mirrors the bash if/elif/else logic)
# ---------------------------------------------------------------------------

def _process_line(line: str, log_type: str) -> None:
    """Parse *line* and route it to the correct InfluxDB measurement."""
    if not _HAS_IP_RE.search(line):
        return

    data = _parse_proxy_line(line) if log_type == 'proxy' else _parse_redirection_line(line)
    if data is None or not data['outside_ip']:
        return

    ip = data['outside_ip']
    domain = data['domain']

    if _is_internal(ip) or _is_external_own(ip):
        _debug_print(f"Internal IP-Source: {ip} called: {domain}")
        if os.getenv('INTERNAL_LOGS') == 'TRUE':
            _send(data, 'InternalRProxyIPs', with_geo=False)

    elif _is_monitor(ip):
        _debug_print(f"Excluded monitoring service: {ip} checked: {domain}")
        if os.getenv('MONITORING_LOGS') == 'TRUE':
            _send(data, 'MonitoringRProxyIPs', with_geo=True)

    elif _is_whitelisted(ip):
        _debug_print(f"Whitelisted IP: {ip} called: {domain} – skipping AbuseIPDB and InfluxDB")
        with _stats_lock:
            _stats['daily_whitelist_hits'] += 1

    else:
        measurement = 'ReverseProxyConnections' if log_type == 'proxy' else 'Redirections'
        _send(data, measurement, with_geo=True)
        _debug_print(f"Data sent: {measurement} – {ip} → {domain}")


# ---------------------------------------------------------------------------
# Log-file tail (one non-daemon thread per file)
# ---------------------------------------------------------------------------

def _tail_file(filepath: str, log_type: str) -> None:
    """Tail *filepath* until the shutdown event is set.

    Handles file rotation by comparing inodes periodically and by reopening
    the file whenever no new data has been seen for *TAIL_NO_DATA_REOPEN_S*
    seconds.  Missing files are retried every 5 seconds so that newly
    rotated files are picked up automatically.
    """
    print(f"[tail] Starting: {filepath}  (type={log_type})")
    while not _shutdown_event.is_set():
        try:
            with open(filepath, 'r', errors='replace') as fh:
                inode = os.fstat(fh.fileno()).st_ino
                fh.seek(0, 2)           # jump to end – skip historical entries
                last_read_time = time.monotonic()
                last_rotation_check = time.monotonic()

                while not _shutdown_event.is_set():
                    line = fh.readline()
                    if line:
                        _process_line(line.rstrip('\n'), log_type)
                        last_read_time = time.monotonic()
                    else:
                        _shutdown_event.wait(timeout=TAIL_SLEEP_S)
                        now = time.monotonic()

                        # Periodic rotation / deletion check
                        if now - last_rotation_check >= TAIL_ROTATION_CHECK_S:
                            last_rotation_check = now
                            try:
                                st = os.stat(filepath)
                                if st.st_ino != inode:
                                    print(f"[tail] Inode changed – file rotated: {filepath}")
                                    break
                                if st.st_size < fh.tell():
                                    print(f"[tail] File truncated: {filepath}")
                                    break
                            except FileNotFoundError:
                                print(f"[tail] File deleted: {filepath}")
                                break

                        # Fallback timeout: reopen if no new data for a long time
                        if now - last_read_time >= TAIL_NO_DATA_REOPEN_S:
                            print(f"[tail] No data for {TAIL_NO_DATA_REOPEN_S}s, reopening: {filepath}")
                            break

        except FileNotFoundError:
            print(f"[tail] File not found: {filepath} – waiting 5s for it to appear…")
            _shutdown_event.wait(timeout=5.0)
        except Exception as exc:
            print(f"[tail] Unexpected error on {filepath}: {exc}")
            _shutdown_event.wait(timeout=5.0)

    with _active_tails_lock:
        _active_tails.pop(filepath, None)
    print(f"[tail] Stopped: {filepath}")


def _start_tail(filepath: str, log_type: str) -> threading.Thread | None:
    """Spawn a non-daemon tail thread for *filepath* unless one is already running."""
    with _active_tails_lock:
        existing = _active_tails.get(filepath)
        if existing is not None and existing.is_alive():
            _debug_print(f"[tail] Already running for: {filepath}")
            return None
        t = threading.Thread(
            target=_tail_file,
            args=(filepath, log_type),
            daemon=False,
            name=f"tail-{os.path.basename(filepath)}",
        )
        t.start()
        _active_tails[filepath] = t
        return t


def _start_initial_watchers(pattern: str, log_type: str) -> list:
    """Start tail threads for all files currently matching *pattern*."""
    matched = sorted(glob.glob(pattern))
    if not matched:
        print(f"[tail] No log files matched pattern: {pattern}")
        return []
    started = []
    for path in matched:
        t = _start_tail(path, log_type)
        if t is not None:
            started.append(t)
    return started


# ---------------------------------------------------------------------------
# Health-check: periodically detect new / rotated files
# ---------------------------------------------------------------------------

def _health_check(patterns: list) -> None:
    """Sweep the log directory at regular intervals.

    * Removes entries for tail threads that have already stopped.
    * Starts new tail threads for files that match a watched pattern but are
      not yet being tailed (covers files created after the initial scan).
    """
    while not _shutdown_event.is_set():
        _shutdown_event.wait(timeout=HEALTH_CHECK_INTERVAL_S)
        if _shutdown_event.is_set():
            break

        # Reap dead threads from the registry
        with _active_tails_lock:
            dead = [p for p, t in _active_tails.items() if not t.is_alive()]
        for path in dead:
            print(f"[health] Tail thread finished for: {path}")
            with _active_tails_lock:
                _active_tails.pop(path, None)

        # Start tails for any newly matching files
        for pattern, log_type in patterns:
            for path in sorted(glob.glob(pattern)):
                with _active_tails_lock:
                    already = path in _active_tails and _active_tails[path].is_alive()
                if not already:
                    print(f"[health] Starting tail for newly found file: {path}")
                    _start_tail(path, log_type)

        # Log current state
        with _active_tails_lock:
            alive_count = sum(1 for t in _active_tails.values() if t.is_alive())
        print(f"[health] Active tail threads: {alive_count}")


# ---------------------------------------------------------------------------
# Watchdog handler: react to filesystem events in the log directory
# ---------------------------------------------------------------------------

class _LogDirectoryHandler(FileSystemEventHandler):
    """Start a tail thread when a new log file matching a watched pattern appears."""

    def __init__(self, patterns: list) -> None:
        # patterns: list of (glob_pattern, log_type)
        self._patterns = patterns

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        path = event.src_path
        for pattern, log_type in self._patterns:
            if fnmatch.fnmatch(path, pattern):
                print(f"[watchdog] New log file detected: {path}")
                _start_tail(path, log_type)
                break

    def on_moved(self, event) -> None:
        # A file was moved *into* the watched directory (rotation destination)
        if event.is_directory:
            return
        path = event.dest_path
        for pattern, log_type in self._patterns:
            if fnmatch.fnmatch(path, pattern):
                print(f"[watchdog] Log file moved/rotated in: {path}")
                _start_tail(path, log_type)
                break


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global _debug_mode, _batch_size, _last_stats_time

    # ------------------------------------------------------------------
    # Debug mode: enabled by --debug CLI argument or DEBUG=true env var
    # ------------------------------------------------------------------
    _debug_mode = (
        '--debug' in sys.argv
        or os.getenv('DEBUG', '').lower() in ('true', '1', 'yes')
    )

    print("npmGrafStats: Unified Python Log Processor")
    if _debug_mode:
        print("Debug mode: ON (verbose per-line logging enabled)")
    else:
        print(
            "Debug mode: OFF  "
            "(pass --debug or set DEBUG=true for verbose logs; "
            f"stats printed every {STATS_INTERVAL_S}s)"
        )

    os.makedirs(DATA_DIR, exist_ok=True)

    _init_geoip()
    _init_abuseip()
    _init_influx()
    _init_external_ip()
    _init_monitor_ips()
    _init_whitelist_ips()

    try:
        _batch_size = int(os.getenv('BATCH_SIZE', '1'))
    except ValueError:
        _batch_size = 1
    print(f"Batch size: {_batch_size}")

    # ------------------------------------------------------------------
    # Register signal handlers for graceful shutdown
    # ------------------------------------------------------------------
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # ------------------------------------------------------------------
    # Determine watch patterns based on REDIRECTION_LOGS mode
    # ------------------------------------------------------------------
    redirection_mode = os.getenv('REDIRECTION_LOGS', '')
    if redirection_mode == 'TRUE':
        print("Mode: Reverse-Proxy + Redirection logs")
        patterns = [
            ('/logs/proxy-host-*_access.log',       'proxy'),
            ('/logs/redirection-host-*_access.log', 'redirection'),
        ]
    elif redirection_mode == 'ONLY':
        print("Mode: Redirection logs only")
        patterns = [('/logs/redirection-host-*_access.log', 'redirection')]
    else:
        print("Mode: Reverse-Proxy logs only")
        patterns = [('/logs/proxy-host-*_access.log', 'proxy')]

    # ------------------------------------------------------------------
    # Start initial tail threads for currently existing log files
    # ------------------------------------------------------------------
    for pattern, log_type in patterns:
        _start_initial_watchers(pattern, log_type)

    with _active_tails_lock:
        initial_count = len(_active_tails)
    if initial_count == 0:
        print("WARNING: No log files found to monitor at startup; waiting for files to appear.")

    # ------------------------------------------------------------------
    # Start watchdog observer to detect new / rotated log files
    # ------------------------------------------------------------------
    log_dir = '/logs'
    observer = None
    if os.path.isdir(log_dir):
        handler = _LogDirectoryHandler(patterns)
        observer = Observer()
        observer.schedule(handler, log_dir, recursive=False)
        observer.start()
        print(f"[watchdog] Monitoring directory: {log_dir}")
    else:
        print(f"[watchdog] WARNING: Log directory not found: {log_dir} – watchdog not started.")

    # ------------------------------------------------------------------
    # Start health-check thread
    # ------------------------------------------------------------------
    health_thread = threading.Thread(
        target=_health_check,
        args=(patterns,),
        daemon=False,
        name='health-check',
    )
    health_thread.start()

    print(f"Monitoring log files. Press Ctrl-C or send SIGTERM to stop.")
    _last_stats_time = time.monotonic()
    try:
        while not _shutdown_event.is_set():
            _shutdown_event.wait(timeout=1.0)
            # Flush any remaining batched points periodically
            if _batch_size > 1:
                to_flush = []
                with _batch_lock:
                    if _batch:
                        to_flush = _batch.copy()
                        _batch.clear()
                if to_flush:
                    _flush_batch(to_flush)
            # Print statistics summary at regular intervals
            if not _debug_mode and time.monotonic() - _last_stats_time >= STATS_INTERVAL_S:
                _print_stats()
                _last_stats_time = time.monotonic()
    except KeyboardInterrupt:
        print("[shutdown] KeyboardInterrupt received.")
        _shutdown_event.set()
    finally:
        print("[shutdown] Stopping background services…")

        # Stop watchdog observer
        if observer is not None:
            observer.stop()
            observer.join(timeout=5.0)

        # Wait for health-check thread
        health_thread.join(timeout=10.0)

        # Wait for all tail threads to finish
        with _active_tails_lock:
            tail_threads = list(_active_tails.values())
        print(f"[shutdown] Waiting for {len(tail_threads)} tail thread(s) to finish…")
        for t in tail_threads:
            t.join(timeout=10.0)

        # Flush remaining batch
        to_flush = []
        with _batch_lock:
            if _batch:
                to_flush = _batch.copy()
                _batch.clear()
        if to_flush:
            _flush_batch(to_flush)

        _print_stats()
        if _city_reader:
            _city_reader.close()
        if _asn_reader:
            _asn_reader.close()
        if _influx_client:
            _influx_client.close()
        print("[shutdown] Shutdown complete.")


if __name__ == '__main__':
    main()
