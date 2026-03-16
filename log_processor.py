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
import ipaddress
import threading
from datetime import datetime

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
# Compiled regular expressions (built once, reused for every log line)
# ---------------------------------------------------------------------------

# Matches IPv4 addresses
_IPV4_RE = re.compile(
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
)

# Matches the content of a log line that contains at least one IPv4 address
_HAS_IP_RE = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')

# Extracts the first domain-like token from a line
# Note: original bash uses {1,3}? where ? makes the group optional (0-3 prefix labels)
_DOMAIN_RE = re.compile(
    r'(?:[a-z0-9\-]*\.){0,3}[a-z0-9\-]*\.[A-Za-z]{2,6}'
)

# Extracts User-Agent from the NPMplus log field "[Sent-to <host>] "<ua>""
_UA_RE = re.compile(r'\[Sent-to [^\]]+\] "([^"]*)"')

# Extracts the forwarded-to host from "[Sent-to <ip>:<port>]"
_SENT_TO_RE = re.compile(r'\[Sent-to ([^\]:]+)(?::\d+)?\]')

# Private / RFC-1918 / loopback / link-local IPv6 ranges
_INTERNAL_IP_RE = re.compile(
    r'(^10(?:\.[0-9]{1,3}){3}$)'
    r'|(^192\.168(?:\.[0-9]{1,3}){2}$)'
    r'|(^172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.[0-9]{1,3}){2}$)'
    r'|(^::1$)'
    r'|(^f[cd][0-9a-fA-F]{2}:)'
    r'|(^fe[89ab][0-9a-fA-F]:)'
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
    """Return all IPv4 addresses found in *line*."""
    return _IPV4_RE.findall(line)


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
    """Parse a proxy-host access log line.

    Field layout (1-indexed, space-delimited as used by the original bash):
      f1=[timestamp  f2=+tz]  f3=outsideip  f4=-  f5=statuscode  …  f14=bytes
    """
    ts = _parse_timestamp(line)
    if ts is None:
        return None
    try:
        fields = line.split(' ')
        statuscode = int(fields[4])         # cut -d' ' -f5
    except (IndexError, ValueError):
        statuscode = 0
    try:
        length_raw = fields[13]             # awk '{print$14}'
        m = re.search(r'\d+', length_raw)
        length = int(m.group()) if m else 0
    except (IndexError, AttributeError):
        length = 0

    ips = _extract_ips(line)
    outside_ip = ips[0] if ips else None
    target_ip = _extract_target_ip(line) or (ips[1] if len(ips) > 1 else outside_ip)

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
    """Parse a redirection-host access log line.

    Field layout (1-indexed, space-delimited as used by the original bash):
      f1=[timestamp  f2=+tz]  f3=statuscode  …
    """
    ts = _parse_timestamp(line)
    if ts is None:
        return None
    try:
        statuscode = int(line.split(' ')[2])   # cut -d' ' -f3
    except (IndexError, ValueError):
        statuscode = 0

    ips = _extract_ips(line)
    outside_ip = ips[0] if ips else None

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
            print(f"AbuseIPDB cache HIT: {ip}")
            return entry['data']

    print(f"AbuseIPDB cache MISS: {ip}")
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
    return bool(_INTERNAL_IP_RE.match(ip))


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
    """Write a list of points to InfluxDB."""
    if not points:
        return
    try:
        _write_api.write(bucket=_influx_bucket, org=_influx_org, record=points)
        print(f"Wrote {len(points)} point(s) to InfluxDB.")
    except Exception as exc:
        print(f"InfluxDB write error: {exc}")


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
        print(f"Internal IP-Source: {ip} called: {domain}")
        if os.getenv('INTERNAL_LOGS') == 'TRUE':
            _send(data, 'InternalRProxyIPs', with_geo=False)

    elif _is_monitor(ip):
        print(f"Excluded monitoring service: {ip} checked: {domain}")
        if os.getenv('MONITORING_LOGS') == 'TRUE':
            _send(data, 'MonitoringRProxyIPs', with_geo=True)

    elif _is_whitelisted(ip):
        print(f"Whitelisted IP: {ip} called: {domain} – skipping AbuseIPDB and InfluxDB")

    else:
        measurement = 'ReverseProxyConnections' if log_type == 'proxy' else 'Redirections'
        _send(data, measurement, with_geo=True)
        print(f"Data sent: {measurement} – {ip} → {domain}")


# ---------------------------------------------------------------------------
# Log-file tail (one thread per file)
# ---------------------------------------------------------------------------

def _tail_file(filepath: str, log_type: str) -> None:
    """Tail *filepath* indefinitely, calling _process_line for each new line."""
    print(f"Tailing: {filepath}  (type={log_type})")
    try:
        with open(filepath, 'r', errors='replace') as fh:
            fh.seek(0, 2)           # jump to end – skip historical entries
            while True:
                line = fh.readline()
                if line:
                    _process_line(line.rstrip('\n'), log_type)
                else:
                    time.sleep(0.05)
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    except Exception as exc:
        print(f"Error tailing {filepath}: {exc}")


def _start_watchers(pattern: str, log_type: str) -> list[threading.Thread]:
    """Spawn a daemon thread for each file matching *pattern*."""
    matched = sorted(glob.glob(pattern))
    if not matched:
        print(f"No log files matched: {pattern}")
        return []
    threads = []
    for path in matched:
        t = threading.Thread(target=_tail_file, args=(path, log_type), daemon=True, name=path)
        t.start()
        threads.append(t)
    return threads


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("npmGrafStats: Unified Python Log Processor")

    os.makedirs(DATA_DIR, exist_ok=True)

    _init_geoip()
    _init_abuseip()
    _init_influx()
    _init_external_ip()
    _init_monitor_ips()
    _init_whitelist_ips()

    global _batch_size
    try:
        _batch_size = int(os.getenv('BATCH_SIZE', '1'))
    except ValueError:
        _batch_size = 1
    print(f"Batch size: {_batch_size}")

    redirection_mode = os.getenv('REDIRECTION_LOGS', '')
    threads: list[threading.Thread] = []

    if redirection_mode == 'TRUE':
        print("Mode: Reverse-Proxy + Redirection logs")
        threads += _start_watchers('/nginx/*access.log',       'proxy')
        threads += _start_watchers('/nginx/redirection-host-*_access.log', 'redirection')
    elif redirection_mode == 'ONLY':
        print("Mode: Redirection logs only")
        threads += _start_watchers('/nginx/redirection-host-*_access.log', 'redirection')
    else:
        print("Mode: Reverse-Proxy logs only")
        threads += _start_watchers('/nginx/*access.log', 'proxy')

    if not threads:
        print("ERROR: No log files found to monitor. Exiting.")
        sys.exit(1)

    print(f"Monitoring {len(threads)} log file(s). Press Ctrl-C to stop.")
    try:
        while True:
            # Flush any remaining batched points periodically
            if _batch_size > 1:
                with _batch_lock:
                    if _batch:
                        to_flush = _batch.copy()
                        _batch.clear()
                        _flush_batch(to_flush)
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down…")
    finally:
        # Flush remaining batch
        with _batch_lock:
            if _batch:
                _flush_batch(_batch.copy())
                _batch.clear()
        if _city_reader:
            _city_reader.close()
        if _asn_reader:
            _asn_reader.close()
        if _influx_client:
            _influx_client.close()


if __name__ == '__main__':
    main()
