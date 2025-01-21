import os
import re
import requests
import csv
import time

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


MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5

def get_geolocation(ip, cache):
    if ip in cache:
        return cache[ip]

    url = f'http://ip-api.com/json/{ip}'
    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = requests.get(url, timeout=10)  # Set timeout to 10 seconds
            response.raise_for_status()  # Raise an error for HTTP errors
            data = response.json()
            geolocation = {
                'postcode': data.get('zip', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'state': data.get('regionName', 'Unknown'),
                'country': data.get('country', 'Unknown')
            }
            cache[ip] = geolocation
            print(f"Fetched geolocation for IP: {ip}")  # Print when geolocation is fetched
            return geolocation
        except requests.exceptions.RequestException as e:
            print("Error fetching geolocation:", e)
            retries += 1
            if retries < MAX_RETRIES:
                print(f"Retrying after {RETRY_DELAY_SECONDS} seconds...")
                time.sleep(RETRY_DELAY_SECONDS)
            else:
                print(f"Max retries reached. Unable to fetch geolocation for IP: {ip}")
                return {
                    'postcode': 'Unknown',
                    'city': 'Unknown',
                    'state': 'Unknown',
                    'country': 'Unknown'
                }


def process_logs(input_dir, output_dir):
    crawler_ips = set()
    facts = []
    dimensions = {}
    dimensions_lookup = {}
    ip_cache = {}  # Cache to store geolocation information for each IP address

    for filename in filter(lambda f: f.endswith('.log'), os.listdir(input_dir)):
        with open(os.path.join(input_dir, filename), 'r', encoding='utf-8') as file:
            for line in file:
                if line.startswith('#') or not line.strip():
                    continue
                parts = re.split(r' (?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)', line.strip())

                if len(parts) < 14:
                    continue

                browser, operating_system = detect_browser_and_os(parts[9].strip('"'))
                file_type = extract_file_type(parts[4].strip('"'))
                dimension_key = (browser, operating_system, file_type)

                if dimension_key not in dimensions_lookup:
                    dimension_id = len(dimensions) + 1
                    dimensions[dimension_id] = dimension_key
                    dimensions_lookup[dimension_key] = dimension_id

                c_ip = parts[8].strip('"')
                if parts[4].strip('"') == '/robots.txt':
                    crawler_ips.add(c_ip)
                    continue

                is_crawler = int(c_ip in crawler_ips)

                # Fetch geolocation information directly for each IP address
                geolocation = get_geolocation(c_ip, ip_cache)

                fact = [dimensions_lookup[dimension_key]] + parts[:9] + [parts[9].strip('"'), parts[10], parts[11],
                                                                         parts[12], parts[13], is_crawler]

                # Append the geolocation information to the fact
                fact.extend(
                    [geolocation['postcode'], geolocation['city'], geolocation['state'], geolocation['country']])

                facts.append(fact)

    write_csv(os.path.join(output_dir, 'facts.csv'),
              ['dimension_id', 'date', 'time', 's-ip', 'cs-method', 'cs-uri-stem', 'cs-uri-query', 's-port',
               'cs-username', 'c-ip', 'cs(User-Agent)', 'sc-status', 'sc-bytes', 'cs-bytes', 'time-taken', 'is_crawler',
               'postcode', 'city', 'state', 'country'], facts)
    write_csv(os.path.join(output_dir, 'dimensions.csv'), ['id', 'browser', 'operating_system', 'file type'],
              [[id] + list(dim) for id, dim in dimensions.items()])


def write_csv(filepath, header, data):
    with open(filepath, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(data)


base_dir = "D:\\BI_pycharm"
input_dir = os.path.join(base_dir, "Data")
output_dir = os.path.join(base_dir, "Output")
os.makedirs(output_dir, exist_ok=True)

process_logs(input_dir, output_dir)
print("Log file processing has been completed.")
