import os
from dotenv import load_dotenv
import requests

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

import json

CACHE_FILE = 'checked_ips.json'

# Load cache
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, 'r') as f:
        ip_cache = json.load(f)
else:
    ip_cache = {}

def check_ip_abuse(ip):
    if ip in ip_cache:
        return ip_cache[ip]  # Return cached result

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            result = {
                "abuse_score": data['abuseConfidenceScore'],
                "country": data.get('countryCode', 'N/A'),
                "isp": data.get('isp', 'N/A'),
                "domain": data.get('domain', 'N/A')
            }
        else:
            result = {
                "abuse_score": 'Error',
                "country": 'Error',
                "isp": 'Error',
                "domain": 'Error'
            }

    except Exception as e:
        print(f"[!] Error checking {ip}: {e}")
        result = {
            "abuse_score": 'Error',
            "country": 'Error',
            "isp": 'Error',
            "domain": 'Error'
        }

    ip_cache[ip] = result

    # Save cache to file
    with open(CACHE_FILE, 'w') as f:
        json.dump(ip_cache, f, indent=2)

    return result



import re
import os
import csv
from datetime import datetime
from collections import defaultdict, Counter
from jinja2 import Environment, FileSystemLoader

# === Settings ===
LOG_PATH = r'C:\Users\Admin\Documents\log-analysis-apache\data\apache_logs.txt'
CSV_OUTPUT = '../output/suspicious_ips_step1.csv'
HTML_OUTPUT = '../output/report.html'
TEMPLATE_DIR = '../templates'

# Suspicious patterns (expand this list as needed)
suspicious_agents_patterns = [
    'curl', 'wget', 'python-requests', 'nmap', 'sqlmap', 'nikto', 'fuzzer', 'scanner',
    'libwww-perl', 'scrapy', 'httpclient', 'bot', 'crawl', 'spider'
]

# === Step 1: Parse Apache Log ===
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) \S+ "(?P<referrer>.*?)" "(?P<useragent>.*?)"'
)

ip_data = defaultdict(lambda: {
    'status_counts': Counter(),
    'methods': Counter(),
    'user_agents': set(),
    'timestamps': [],
    'first_seen': None,
    'last_seen': None,
    'total_requests': 0,
    'suspicious_agent': False
})

with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        match = log_pattern.search(line)
        if not match:
            continue

        ip = match.group('ip')
        status = match.group('status')
        method = match.group('method')
        user_agent = match.group('useragent')
        timestamp = datetime.strptime(match.group('time').split()[0], '%d/%b/%Y:%H:%M:%S')

        data = ip_data[ip]
        data['status_counts'][status] += 1
        data['methods'][method] += 1
        data['user_agents'].add(user_agent)
        data['timestamps'].append(timestamp)
        data['total_requests'] += 1

        if data['first_seen'] is None or timestamp < data['first_seen']:
            data['first_seen'] = timestamp
        if data['last_seen'] is None or timestamp > data['last_seen']:
            data['last_seen'] = timestamp

        # Check if user-agent is suspicious
        if any(pattern in user_agent.lower() for pattern in suspicious_agents_patterns):
            data['suspicious_agent'] = True

# === Step 2: Analyze & Save to CSV + Prepare for HTML ===
data_rows = []

for ip, data in ip_data.items():
    total_401 = data['status_counts'].get('401', 0)
    total_403 = data['status_counts'].get('403', 0)
    total_404 = data['status_counts'].get('404', 0)
    total_requests = data['total_requests']
    total_errors = total_401 + total_403 + total_404
    error_ratio = total_errors / total_requests if total_requests else 0

    suspicious_behavior = (
        error_ratio > 0.8
        or total_403 > 10
        or total_404 == total_requests
    )

    suspicious_agent = data['suspicious_agent']

    if suspicious_agent and suspicious_behavior:
        suspicious_label = "Agent & Behavior"
    elif suspicious_agent:
        suspicious_label = "Agent"
    elif suspicious_behavior:
        suspicious_label = "Behavior"
    else:
        continue  # Skip normal

    abuse_data = check_ip_abuse(ip)

    data_rows.append({
        "ip": ip,
        "total": total_requests,
        "code_401": total_401,
        "code_403": total_403,
        "code_404": total_404,
        "errors": total_errors,
        "error_ratio": f"{error_ratio:.2f}",
        "method": ', '.join(data['methods'].keys()),
        "first": data['first_seen'].strftime('%Y-%m-%d %H:%M'),
        "last": data['last_seen'].strftime('%Y-%m-%d %H:%M'),
        "agent": '; '.join(data['user_agents']),
        "abuse_score": abuse_data["abuse_score"],
        "country": abuse_data["country"],
        "isp": abuse_data["isp"],
        "domain": abuse_data["domain"],
        "flag": suspicious_label
    })




# Sort by errors then total requests
data_rows = sorted(data_rows, key=lambda x: (x['errors'], x['total']), reverse=True)

# Save CSV
os.makedirs(os.path.dirname(CSV_OUTPUT), exist_ok=True)

with open(CSV_OUTPUT, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = [
        "ip", "total", "code_401", "code_403", "code_404", "errors", "error_ratio",
        "method", "first", "last", "agent",
        "abuse_score", "country", "isp", "domain", "flag"
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for row in data_rows:
        writer.writerow(row)

print(f"[DEBUG] Total suspicious IPs in report: {len(data_rows)}")


# === Step 3: Generate HTML Report ===
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
template = env.get_template('report.html')

html_content = template.render(data=data_rows)

with open(HTML_OUTPUT, 'w', encoding='utf-8') as f:
    f.write(html_content)

print("[+] HTML report generated at:", HTML_OUTPUT)

import matplotlib.pyplot as plt
import csv

# Load suspicious IPs
csv_path = '../output/suspicious_ips_step1.csv'
ip_data = []

with open(csv_path, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        ip_data.append({
            'ip': row['ip'],
            'errors': int(row['errors']),
        })

# Sort and get top 10
top_ips = sorted(ip_data, key=lambda x: x['errors'], reverse=True)[:10]
ips = [x['ip'] for x in top_ips]
errors = [x['errors'] for x in top_ips]

# Plot
plt.figure(figsize=(10, 6))
plt.barh(ips, errors, color='darkred')
plt.xlabel('Total 401/403/404 Errors')
plt.title('Top 10 Suspicious IPs by Error Count')
plt.gca().invert_yaxis()
plt.tight_layout()

# Save chart
chart_path = '../output/chart.png'
plt.savefig(chart_path)
print(f'[+] Bar chart saved to {chart_path}')
