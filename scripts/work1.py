import os
import csv
import re


def parse_user_agent(ua_string):
    # Define simple patterns for common browsers and operating systems
    browser_patterns = {
        'Firefox': 'Firefox|Mozilla.*Firefox',
        'MSIE': 'MSIE|Trident',
        'Chrome': 'Chrome',
        'Safari': 'Safari',
        'Opera': 'Opera|OPR',
        'Edge': 'Edge'
    }
    os_patterns = {
        'Windows': 'Windows NT|Win(?!.*PPC)',
        'Mac OS': 'Macintosh|Mac OS X',
        'Linux': 'Linux',
        'iOS': 'iPhone|iPad|iPod',
        'Android': 'Android'
    }

    browser = 'Unknown'
    os = 'Unknown'

    for name, pattern in browser_patterns.items():
        if re.search(pattern, ua_string, re.IGNORECASE):
            browser = name
            break

    for name, pattern in os_patterns.items():
        if re.search(pattern, ua_string, re.IGNORECASE):
            os = name
            break

    return {'browser': browser, 'os': os}


def clean_and_parse_log_files(log_files, output_dir):
    facts = []
    dimensions = set()

    for log_file in log_files:
        with open(log_file, 'r') as file:
            reader = csv.reader(file, delimiter=' ')
            for row in reader:
                if not row or row[0].startswith('#'):
                    continue

                # Identify the start of the user agent data
                for i in range(8, len(row)):
                    if "Mozilla" in row[i] or "MSIE" in row[i] or "Opera" in row[i] or "Chrome" in row[i] or "Safari" in \
                            row[i]:
                        start_index = i
                        break
                else:
                    continue

                ua_string = " ".join(row[start_index:-1])
                user_agent_data = parse_user_agent(ua_string)
                referer = row[-1]

                dimensions.add((user_agent_data['browser'], user_agent_data['os']))

                adjusted_row = row[:start_index] + [user_agent_data['browser'], user_agent_data['os'], referer]
                facts.append(adjusted_row)

    # Write facts to CSV
    with open(os.path.join(output_dir, 'facts.csv'), 'w', newline='') as f:
        writer = csv.writer(f)
        headers = ['date', 'time', 's-ip', 'cs-method', 'cs-uri-stem', 'cs-uri-query', 's-port', 'cs-username', 'c-ip',
                   'Browser', 'OS', 'sc-status', 'sc-substatus', 'sc-win32-status', 'time-taken', 'Referer']
        writer.writerow(headers)
        writer.writerows(facts)

    # Write dimensions to CSV
    with open(os.path.join(output_dir, 'dimensions.csv'), 'w', newline='') as f:
        writer = csv.writer(f)
        headers = ['browser', 'os']
        writer.writerow(headers)
        for dimension in dimensions:
            writer.writerow(dimension)

base_dir = "D:\\BI_pycharm"
data_dir = os.path.join(base_dir, "Data")
output_dir = os.path.join(base_dir, "Output") # Update this with your desired output directory

# Ensure the output directory exists
os.makedirs(output_dir, exist_ok=True)

# Process and clean log files
clean_and_parse_log_files(data_dir, output_dir)
