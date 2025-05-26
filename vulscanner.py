import requests
import sqlite3
import threading
import time
import os
import sys
import re
import json
from datetime import datetime
from bs4 import BeautifulSoup

CVE_API_URL = " "
db_path = "vulns.db"
report_dir = "reports"
update_interval = 3600

os.makedirs(report_dir, exist_ok=True)

def init_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            published TEXT,
            last_modified TEXT
        )
    ''')
    conn.commit()
    conn.close()

last_mod_date = datetime.utcnow().isoformat() + "Z"
def update_cve_db():
    global last_mod_date
    while True:
        try:
            url = CVE_API_URL.format(last_mod_date)
            print(f"[CVEUpdater] Checking NVD for updates since {last_mod_date}...")
            r = requests.get(url)
            data = r.json()
            new_items = 0
            if 'vulnerabilities' in data:
                conn = sqlite3.connect(db_path)
                c = conn.cursor()
                for item in data['vulnerabilities']:
                    cve = item['cve']
                    cve_id = cve['id']
                    description = cve['descriptions'][0]['value']
                    published = cve['published']
                    last_modified = cve['lastModified']
                    try:
                        c.execute("INSERT INTO cves VALUES (?, ?, ?, ?)", (cve_id, description, published, last_modified))
                        new_items += 1
                    except sqlite3.IntegrityError:
                        continue
                conn.commit()
                conn.close()
                print(f"[CVEUpdater] Added {new_items} new CVEs")
            last_mod_date = datetime.utcnow().isoformat() + "Z"
        except Exception as e:
            print(f"[CVEUpdater] Error: {e}")
        time.sleep(update_interval)

def scan_site(url):
    report = []
    try:
        r = requests.get(url)
        headers = r.headers
        report.append(f"[+] Server responded with status code {r.status_code}")
        if 'Server' in headers:
            report.append(f"[+] Server header: {headers['Server']}")
        if 'X-Powered-By' in headers:
            report.append(f"[+] X-Powered-By: {headers['X-Powered-By']}")

        soup = BeautifulSoup(r.text, 'lxml')
        forms = soup.find_all('form')
        if forms:
            report.append(f"[+] Found {len(forms)} HTML form(s) (potential injection points)")
            for form in forms:
                action = form.get('action') or url
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                for i in inputs:
                    name = i.get('name')
                    if name:
                        payloads = [
                            ("XSS", '<script>alert(1)</script>'),
                            ("SQLi", "' OR '1'='1")
                        ]
                        for label, payload in payloads:
                            test_data = {name: payload}
                            try:
                                if method == 'post':
                                    fr = requests.post(url + action, data=test_data)
                                else:
                                    fr = requests.get(url + action, params=test_data)
                                if payload in fr.text:
                                    report.append(f"[!] Possible {label} vulnerability in form at {action}")
                            except:
                                continue

        if "../" in r.text:
            report.append("[!] Possible Directory Traversal strings detected")

        tech = []
        if 'php' in r.text:
            tech.append('PHP')
        if 'wp-content' in r.text:
            tech.append('WordPress')
        if 'jquery' in r.text:
            tech.append('jQuery')
        if tech:
            report.append(f"[+] Detected technologies: {', '.join(tech)}")

    except Exception as e:
        report.append(f"[!] Error accessing site: {e}")
    return report

def check_known_vulns(url):
    findings = []
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    r = requests.get(url)
    server_header = r.headers.get('Server', '').lower()
    c.execute("SELECT * FROM cves WHERE description LIKE ?", (f"%{server_header}%",))
    rows = c.fetchall()
    if rows:
        findings.append(f"[!] Found {len(rows)} known CVEs related to server: {server_header}")
        for row in rows[:10]:
            findings.append(f"  - {row[0]}: {row[1][:100]}...")
    conn.close()
    return findings

def save_report(domain, lines):
    now = datetime.now().strftime("%Y-%m-%d-%H%M")
    base_name = domain.replace('https://','').replace('http://','').replace('/', '')
    md_file = os.path.join(report_dir, f"report-{now}-{base_name}.md")
    html_file = os.path.join(report_dir, f"report-{now}-{base_name}.html")

    with open(md_file, 'w', encoding='utf-8') as f:
        for line in lines:
            f.write(line + "\n")

    html_content = "<html><head><meta charset='utf-8'><title>Scan Report</title><style>body{font-family:sans-serif;padding:20px;} h2{color:#333;} .alert{color:red;}</style></head><body>"
    html_content += f"<h1>Scan Report for {domain}</h1><p>Generated at: {datetime.now().isoformat()}</p>"
    for line in lines:
        if line.startswith("[!]"):
            html_content += f"<p class='alert'>{line}</p>"
        else:
            html_content += f"<p>{line}</p>"
    html_content += "</body></html>"

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[+] Reports saved: {md_file}, {html_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vuln_scanner.py <url>")
        print("Example: python vuln_scanner.py http://example.com")
        print("Exiting... No URL provided.")
        sys.exit(0)

    url = sys.argv[1]
    print(f"[+] Starting scan on {url}")

    init_db()
    threading.Thread(target=update_cve_db, daemon=True).start()

    results = []
    results.append("# Vulnerability Scan Report")
    results.append(f"**Target:** {url}")
    results.append(f"**Scanned at:** {datetime.now().isoformat()}")
    results.append("\n## Basic Web Scan")
    results += scan_site(url)
    results.append("\n## Known CVEs")
    results += check_known_vulns(url)
    save_report(url, results)
