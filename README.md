# Apache Log Analyzer with Threat Intelligence

This project analyzes Apache HTTP logs to detect suspicious IP addresses using log behavior and user-agent analysis. It integrates AbuseIPDB for threat intelligence and generates both CSV and HTML reports with charts.

## 🔍 Features

- Parses Apache log files
- Detects suspicious activity:
  - High 401/403/404 error ratios
  - Suspicious user agents (e.g., curl, sqlmap)
- Integrates AbuseIPDB for abuse confidence score, country, ISP, and domain info
- Outputs:
  - CSV report
  - Printable HTML report
  - Bar chart of top offending IPs

## 📁 Project Structure

log-analysis-apache/
│
├── data/
│ └── apache_logs.txt # Your sample Apache log file
│
├── output/
│ ├── suspicious_ips_step1.csv # CSV summary of suspicious IPs
│ ├── report.html # Full HTML report
│ └── chart.png # Bar chart of top IPs
│
├── scripts/
│ ├── analyze_logs.py # Main script
│ ├── checked_ips.json # Cache of AbuseIPDB results
│ ├── .env # Contains API key (excluded from Git)
│ └── requirements.txt # Python dependencies
│
├── templates/
│ └── report.html # HTML report template (Jinja2)
│
├── .gitignore
└── README.md

bash
Copy
Edit

## ⚙️ Setup

1. **Clone the repo**

```bash
git clone https://github.com/sufrizand/apache-log-analyzer.git
cd apache-log-analyzer
Set up a virtual environment (optional but recommended)

bash
Copy
Edit
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # macOS/Linux
Install dependencies

bash
Copy
Edit
pip install -r scripts/requirements.txt
Add AbuseIPDB API key

Create a .env file inside scripts/:

env
Copy
Edit
ABUSEIPDB_API_KEY=your_api_key_here
(You can get a free API key from AbuseIPDB.)

Run the analyzer

bash
Copy
Edit
python scripts/analyze_logs.py
This will generate:

output/suspicious_ips_step1.csv

output/report.html

output/chart.png

📊 Sample Report


✅ TODO (optional future upgrades)
Export to PDF

Email alert system

Real-time log monitoring

Docker support

Integration into a SIEM or dashboard