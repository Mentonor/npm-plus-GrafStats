#!/usr/bin/python3

import sys
import os
import geoip2.database
import socket
import json
import time
import fcntl
from datetime import datetime, timedelta
import ipaddress
from ipaddress import ip_address, IPv4Network, IPv6Network, AddressValueError
import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS
from ua_parser import user_agent_parser

print ('**************** start plus *********************')
measurement_name = (sys.argv[4]) # get measurement from argv
print ('Measurement-name: '+measurement_name) 

# argv[1[] = outsideip, agrv[2] = Domain, argv[3] length,  sys.argv[4] bucketname, sys.argv[5] date, sys.argv[6] asn, sys.argv[7] statuscode, sys.argv[8] useragent

# Configuration for Persistent Data
DATA_DIR = "/data"
CACHE_FILE = os.path.join(DATA_DIR, "abuseip_cache.json")
CACHE_EXPIRATION_HOURS = 48
INFLUX_TOKEN_FILE = os.path.join(DATA_DIR, "influxdb-token.txt")
ABUSEIP_KEY_FILE = os.path.join(DATA_DIR, "abuseipdb-key.txt")
IP_WHITELIST_FILE = os.path.join(DATA_DIR, "ip_whitelist.txt")

# Ensure the data directory exists
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# ============ WHITELIST MANAGEMENT ============

def load_whitelist():
    """Load IP whitelist from file or environment variable"""
    whitelist = []
    
    # Try to load from environment variable first
    env_whitelist = os.getenv('IP_WHITELIST')
    if env_whitelist:
        whitelist_str = env_whitelist.split(',')
    # Then try to load from file
    elif os.path.exists(IP_WHITELIST_FILE):
        try:
            with open(IP_WHITELIST_FILE, 'r') as f:
                whitelist_str = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except (IOError, OSError) as e:
            print(f"Error loading whitelist file: {e}")
            whitelist_str = []
    else:
        whitelist_str = []
    
    # Parse whitelist entries
    for entry in whitelist_str:
        entry = entry.strip()
        if not entry or entry.startswith('#'):
            continue
        try:
            # Try to parse as CIDR network
            if '/' in entry:
                whitelist.append(ip_network(entry, strict=False))
            else:
                # Parse as single IP address
                whitelist.append(ip_address(entry))
        except AddressValueError as e:
            print(f"Warning: Invalid whitelist entry '{entry}': {e}")
    
    return whitelist

def is_ip_whitelisted(ip_str, whitelist):
    """Check if IP is in whitelist (supports both single IPs and CIDR ranges)"""
    try:
        ip_obj = ip_address(ip_str)
        for entry in whitelist:
            if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if ip_obj in entry:
                    return True
            else:  # single IP address
                if ip_obj == entry:
                    return True
    except AddressValueError:
        print(f"Warning: Invalid IP address format: {ip_str}")
    return False

# Load whitelist once at startup
whitelist = load_whitelist()
if whitelist:
    print(f"Whitelist loaded: {len(whitelist)} entries")

# ============ CACHE MANAGEMENT ============

def load_cache():
    """Load the cache from the file"""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock
            data = json.load(f)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            return data
    except (json.JSONDecodeError, IOError, OSError) as e:
        print(f"Error loading cache: {e}")
        return {}

def save_cache(cache_data):
    """Save the cache to the file"""
    try:
        with open(CACHE_FILE, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # Exclusive lock
            json.dump(cache_data, f, indent=4)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except (IOError, OSError) as e:
        print(f"Error saving cache: {e}")

def get_abuseip_info(ip_address):
    """Get AbuseIPDB info using cache"""
    cache = load_cache()
    current_time = time.time()

    # Check if a valid, non-expired entry exists in the cache
    if ip_address in cache:
        entry = cache[ip_address]
        entry_time = entry.get('timestamp', 0)
        if current_time - entry_time < CACHE_EXPIRATION_HOURS * 3600:
            print(f"Cache HIT for IP: {ip_address}")
            return entry['data']

    # If not in cache or expired, fetch from API
    print(f"Cache MISS for IP: {ip_address}. Fetching from API.")
    
    if os.path.exists(ABUSEIP_KEY_FILE):
        with open(ABUSEIP_KEY_FILE, 'r') as file:
            abuseip_key = file.read().strip()
    elif os.getenv('ABUSEIP_KEY') is not None:
        abuseip_key = os.getenv('ABUSEIP_KEY')
    else:
        return None

    try:
        import requests
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': abuseip_key}

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        response.raise_for_status()

        api_data = response.json().get("data")
        if api_data:
            cache[ip_address] = {'timestamp': current_time, 'data': api_data}
            save_cache(cache)
        return api_data
    except Exception as e:
        print(f"API request failed: {e}")
        return None

# ============ INITIALIZE GEOIP READERS (CPU OPTIMIZATION) ============
# Keep readers open for the duration of script execution instead of opening/closing repeatedly

try:
    geoip_city_reader = geoip2.database.Reader('/geolite/GeoLite2-City.mmdb')
    print("GeoLite2-City reader initialized")
except Exception as e:
    print(f"Error initializing GeoLite2-City reader: {e}")
    sys.exit(1)

geoip_asn_reader = None
if str(sys.argv[6]) == 'true':
    try:
        geoip_asn_reader = geoip2.database.Reader('/geolite/GeoLite2-ASN.mmdb')
        print("GeoLite2-ASN reader initialized")
    except Exception as e:
        print(f"Error initializing GeoLite2-ASN reader: {e}")

# ============ MAIN PROCESSING ============

# Get IP geolocation data
try:
    response = geoip_city_reader.city(str(sys.argv[1]))
    Lat = response.location.latitude
    ISO = response.country.iso_code
    Long = response.location.longitude
    State = response.subdivisions.most_specific.name if response.subdivisions else "Unknown"
    City = response.city.name if response.city.name else "Unknown"
    Country = response.country.name
    Zip = response.postal.code if response.postal.code else "Unknown"
except Exception as e:
    print(f"Error retrieving GeoIP data: {e}")
    geoip_city_reader.close()
    if geoip_asn_reader:
        geoip_asn_reader.close()
    sys.exit(1)

IP = str(sys.argv[1])
Domain = str(sys.argv[2])
length = int(sys.argv[3])
statuscode = int(sys.argv[7])
useragent = str(sys.argv[8])
asn = str(sys.argv[6])

Asn = None
if asn == 'true' and geoip_asn_reader:
    try:
        response = geoip_asn_reader.asn(str(sys.argv[1]))
        Asn = response.autonomous_system_organization
    except Exception as e:
        print(f"Error retrieving ASN data: {e}")
        Asn = "Unknown"

# Parse User-Agent
parsed_ua = user_agent_parser.Parse(useragent)
browser = parsed_ua['user_agent']['family'] or 'Unknown'
browser_only_version = parsed_ua['user_agent']['major'] or '0'
browser_version = browser + ": " + browser_only_version
if parsed_ua['user_agent']['minor']:
    browser_version += '.' + parsed_ua['user_agent']['minor']
os_family = parsed_ua['os']['family'] or 'Unknown'

# AbuseIPDB data - only fetch if IP is not whitelisted
abuseConfidenceScore = "0"
totalReports = "0"
abuseip_key = None

if is_ip_whitelisted(IP, whitelist):
    print(f"IP {IP} is whitelisted - skipping AbuseIPDB check")
else:
    if os.path.exists(ABUSEIP_KEY_FILE):
        with open(ABUSEIP_KEY_FILE, 'r') as file:
            abuseip_key = file.read().strip()
    elif os.getenv('ABUSEIP_KEY') is not None:
        abuseip_key = os.getenv('ABUSEIP_KEY')
    
    if abuseip_key:
        abuseip_data = get_abuseip_info(sys.argv[1])
        if abuseip_data:
            abuseConfidenceScore = str(abuseip_data.get("abuseConfidenceScore", "0"))
            totalReports = str(abuseip_data.get("totalReports", "0"))

# Print to log
print(Country)
print(State)
print(City)
print(Zip)
print(Long)
print(Lat)
print(ISO)
if asn == 'true' and Asn:
    print(Asn)
print('Outside IP: ', IP)
print('Domain: ', Domain)
print('Statuscode ', statuscode)
if abuseip_key:
    print("abuseConfidenceScore: " + abuseConfidenceScore)
    print("totalReports: " + totalReports)
print("Browser Version:", browser_version)
print("OS Family:", os_family)

# InfluxDB configuration
npmhome = "/home/appuser/.config/NPMGRAF"
ifhost = os.getenv('INFLUX_HOST')
ifbucket = os.getenv('INFLUX_BUCKET')
iforg = os.getenv('INFLUX_ORG')

if os.getenv('INFLUX_TOKEN') is not None:
    iftoken = os.getenv('INFLUX_TOKEN')
elif os.path.exists(INFLUX_TOKEN_FILE):
    with open(INFLUX_TOKEN_FILE, 'r') as file:
        iftoken = file.read().strip()
else:
    print('No InfluxDB Token found.')
    print('Please add the Token. Exiting now.')
    geoip_city_reader.close()
    if geoip_asn_reader:
        geoip_asn_reader.close()
    sys.exit(1)

# Take a timestamp for this measurement
oldtime = str(sys.argv[5])
month_map = {'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06', 
             'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'}
month = month_map.get(oldtime[3:6], '12')
time_str = f"{oldtime[7:11]}-{month}-{oldtime[0:2]}T{oldtime[12:20]}{oldtime[21:24]}:{oldtime[24:26]}"
print('Measurement Time: ', time_str)

# Initialize InfluxDB client
try:
    ifclient = influxdb_client.InfluxDBClient(
        url=ifhost,
        token=iftoken,
        org=iforg
    )
except Exception as e:
    print(f"Error initializing InfluxDB client: {e}")
    geoip_city_reader.close()
    if geoip_asn_reader:
        geoip_asn_reader.close()
    sys.exit(1)

# Write the measurement
write_api = ifclient.write_api(write_options=SYNCHRONOUS)

point = influxdb_client.Point(measurement_name)
point.tag("key", ISO)
point.tag("latitude", Lat)
point.tag("longitude", Long)
point.tag("Domain", Domain)
point.tag("City", City)
point.tag("State", State)
point.tag("Name", Country)
point.tag("IP", IP)
if asn == 'true' and Asn:
    point.tag("Asn", Asn)
if abuseip_key:
    point.tag("abuseConfidenceScore", abuseConfidenceScore)
    point.tag("totalReports", totalReports)

point.field("Domain", Domain)
point.field("latitude", Lat)
point.field("longitude", Long)
point.field("State", State)
point.field("City", City)
point.field("key", ISO)
point.field("IP", IP)
if asn == 'true' and Asn:
    point.field("Asn", Asn)
point.field("Name", Country)
point.field("length", length)
point.field("statuscode", statuscode)
point.field("metric", 1)
if abuseip_key:
    point.field("abuseConfidenceScore", abuseConfidenceScore)
    point.field("totalReports", totalReports)
point.field("browser", browser)
point.field("browser_version", browser_version)
point.field("os", os_family)

point.time(time_str)

try:
    write_api.write(bucket=ifbucket, org=iforg, record=point)
    print('Data sent to InfluxDB successfully')
except Exception as e:
    print(f"Error writing to InfluxDB: {e}")

ifclient.close()
geoip_city_reader.close()
if geoip_asn_reader:
    geoip_asn_reader.close()

print ('*************** plus data send ******************')
