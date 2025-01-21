import os
import re
import requests
import csv
import time
from datetime import datetime

MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5

def detect_browser_and_os(ua_string):
    browser_patterns = {
        'Firefox': ['Firefox'],
        'MSIE': ['MSIE', 'Trident'],
        'Chrome': ['Chrome'],
        'Safari': ['Safari', 'AppleWebKit'],
        'Opera': ['Opera', 'OPR'],
        'Edge': ['Edge'],
        'Netscape': ['Netscape'],
        'Baiduspider': ['Baiduspider'],
        'YandexBot': ['YandexBot'],
        'Sogou': ['Sogou'],
        'Panscient': ['panscient.com'],
        'msnbot': ['msnbot']
    }
    operating_system_patterns = {
        'Windows': ['Windows NT', 'Win(?!.*PPC)'],
        'Mac OS': ['Macintosh', 'Mac OS X'],
        'Linux': ['Linux'],
        'iOS': ['iPhone', 'iPad', 'iPod'],
        'Android': ['Android']
    }

    browser, operating_system = 'Unknown', 'Unknown'
    for name, patterns in browser_patterns.items():
        if any(re.search(pattern, ua_string, re.IGNORECASE) for pattern in patterns):
            browser = name
            break
    for name, patterns in operating_system_patterns.items():
        if any(re.search(pattern, ua_string, re.IGNORECASE) for pattern in patterns):
            operating_system = name
            break
    return browser, operating_system

def extract_file_type(uri_stem):
    match = re.search(r'\.(\w+)$', uri_stem)
    return match.group(1) if match else 'None'

def get_geolocation(ip, cache):
    if ip in cache:
        print(f"Cache hit for IP: {ip}")
        return cache[ip]

    url = f'http://ip-api.com/json/{ip}'
    retries = 0
    delay = RETRY_DELAY_SECONDS

    while retries < MAX_RETRIES:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 429:
                raise requests.exceptions.RequestException("429 Too Many Requests")
            response.raise_for_status()  # Raises an error for HTTP errors
            data = response.json()
            geolocation = {
                'postcode': data.get('zip', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'state': data.get('regionName', 'Unknown'),
                'country': data.get('country', 'Unknown')
            }
            cache[ip] = geolocation
            print(f"Fetched geolocation for IP {ip}: {geolocation}")
            return geolocation
        except requests.exceptions.RequestException as e:
            print(f"Error fetching geolocation for {ip}: {e}. Retrying in {delay} seconds...")
            time.sleep(delay)
            retries += 1
            delay *= 2  # Exponential backoff

    print(f"Max retries reached for IP {ip}. Using default geolocation.")
    return {'postcode': 'Unknown', 'city': 'Unknown', 'state': 'Unknown', 'country': 'Unknown'}

def process_logs(input_dir, output_dir):
    staging_dir = os.path.join(output_dir, "staging")
    os.makedirs(staging_dir, exist_ok=True)

    browsers = {}
    operating_systems = {}
    file_types = {}
    dates = {}
    ips = {}
    geolocations = {}
    facts = []

    browser_id, os_id, file_type_id, date_id, ip_id, geo_id, crawler_id = 1, 1, 1, 1, 1, 1, 1
    ip_cache = {}
    geo_cache = {}

    crawler_ips = set()
    crawler_data = []

    for filename in filter(lambda f: f.endswith('.log'), os.listdir(input_dir)):
        with open(os.path.join(input_dir, filename), 'r', encoding='utf-8') as file:
            for line in file:
                if line.startswith('#') or not line.strip():
                    continue
                parts = re.split(r' (?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)', line.strip())
                if len(parts) < 14:
                    continue

                date_str, time_str, ip_address = parts[0], parts[1], parts[8].strip('"')
                browser_name, os_name = detect_browser_and_os(parts[9].strip('"'))
                file_type_name = extract_file_type(parts[4].strip('"'))
                date_key = datetime.strptime(date_str, "%Y-%m-%d").date()

                if parts[4].strip('"') == '/robots.txt':
                    crawler_ips.add(ip_address)
                    continue

                is_crawler = int(ip_address in crawler_ips)
                crawler_data.append([ip_address, is_crawler])

                if browser_name not in browsers:
                    browsers[browser_name] = browser_id
                    browser_id += 1
                if os_name not in operating_systems:
                    operating_systems[os_name] = os_id
                    os_id += 1
                if file_type_name not in file_types:
                    file_types[file_type_name] = file_type_id
                    file_type_id += 1
                if date_key not in dates:
                    dates[date_key] = date_id
                    date_id += 1
                if ip_address not in ips:
                    ips[ip_address] = ip_id
                    ip_id += 1

                geolocation = get_geolocation(ip_address, geo_cache)
                geo_key = (geolocation['postcode'], geolocation['city'], geolocation['state'], geolocation['country'])
                if geo_key not in geolocations:
                    geolocations[geo_key] = geo_id
                    geo_id += 1

                facts.append([date_str, time_str, parts[2], parts[3], parts[4], parts[5], parts[6], parts[7], ip_address, parts[9].strip('"'), parts[10], parts[11], parts[12], parts[13], browsers[browser_name], operating_systems[os_name], file_types[file_type_name], dates[date_key], ips[ip_address], geolocations[geo_key], is_crawler])

    write_csv(os.path.join(staging_dir, 'browsers.csv'), ['id', 'name'], [[v, k] for k, v in browsers.items()])
    write_csv(os.path.join(staging_dir, 'operating_systems.csv'), ['id', 'name'], [[v, k] for k, v in operating_systems.items()])
    write_csv(os.path.join(staging_dir, 'file_types.csv'), ['id', 'name'], [[v, k] for k, v in file_types.items()])
    write_csv(os.path.join(staging_dir, 'dates.csv'), ['id', 'date'], [[v, k] for k, v in dates.items()])
    write_csv(os.path.join(staging_dir, 'ips.csv'), ['id', 'ip_address'], [[v, k] for k, v in ips.items()])
    write_csv(os.path.join(staging_dir, 'geolocations.csv'), ['id', 'postcode', 'city', 'state', 'country'], [[v, *k] for k, v in geolocations.items()])
    write_csv(os.path.join(staging_dir, 'crawler_data.csv'), ['ip_address', 'is_crawler'], crawler_data)
    write_csv(os.path.join(staging_dir, 'facts.csv'), ['date', 'time', 'method', 'uri_stem', 'uri_query', 'status', 'bytes_sent', 'referrer', 'ip_address', 'browser', 'referrer_domain', 'search_engine', 'search_term', 'user_agent', 'browser_id', 'os_id', 'file_type_id', 'date_id', 'ip_id', 'geolocation_id', 'is_crawler'], facts)

def write_csv(file_path, header, rows):
    with open(file_path, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)


# Define file paths and execute processing
base_dir = "D:\\BI_pycharm"
input_dir = os.path.join(base_dir, "Data")
output_dir = os.path.join(base_dir, "Output")
process_logs(input_dir, output_dir)
