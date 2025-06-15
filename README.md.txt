# 🛡️ Suspicious IP Log Analyzer

A beginner-friendly log analysis tool that detects suspicious IP behavior from Apache access logs. It integrates threat intelligence using AbuseIPDB, generates a CSV and HTML report, and visualizes top offending IPs using a bar chart.

## 🔍 Features

- Parses Apache access logs for:
  - Status codes (401, 403, 404)
  - Request methods
  - User agents
  - Timestamps
- Detects suspicious IPs based on:
  - High error ratios
  - Repeated access denials
  - Suspicious user agents
- Integrates with [AbuseIPDB](https://www.abuseipdb.com/) to enrich data
- Outputs:
  - `CSV` report of flagged IPs
  - `HTML` report with formatted table and threat flags
  - `PNG` chart of top 10 offending IPs by error count
- Caches IP lookup results to avoid redundant API calls

## 📁 Project Structure

