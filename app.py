from flask import Flask, request, send_file
from collections import Counter
import matplotlib.pyplot as plt
import os
import csv
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("static", exist_ok=True)

report_data = []

# 🔹 Attack Classification
def classify_attack(line):
    line_lower = line.lower()

    if "../" in line:
        return "Directory Traversal", "High"
    elif "login" in line_lower:
        return "Brute Force Attempt", "High"
    elif "select" in line_lower or "union" in line_lower or "or 1=1" in line_lower:
        return "SQL Injection", "High"
    elif "/admin" in line_lower:
        return "Admin Panel Scan", "Medium"
    else:
        return "Normal Traffic", "Low"

# 🔹 Log Analysis
def analyze_log(file_path):
    ips = []
    suspicious = []
    global report_data
    report_data = []

    with open(file_path) as f:
        for line in f:
            parts = line.split()
            if len(parts) > 8:
                ip = parts[0]
                status = parts[8]

                ips.append(ip)

                attack, severity = classify_attack(line)

                if status == "404":
                    suspicious.append(ip)

                if attack != "Normal Traffic":
                    report_data.append(f"{ip} → {attack} ({severity})")

    return Counter(ips).most_common(5), Counter(suspicious).most_common(5)

# 🔹 Graph
def generate_graph(data):
    if not data:
        return

    ips = [ip for ip, count in data]
    counts = [count for ip, count in data]

    plt.figure()
    plt.bar(ips, counts)
    plt.title("Top IP Activity")
    plt.xlabel("IP Address")
    plt.ylabel("Requests")
    plt.savefig("static/graph.png")
    plt.close()

# 🔹 PDF Report
def generate_pdf():
    doc = SimpleDocTemplate("report.pdf")
    styles = getSampleStyleSheet()

    content = []
    content.append(Paragraph("DFIR Forensic Report", styles["Title"]))

    for item in report_data:
        content.append(Paragraph(item, styles["Normal"]))

    doc.build(content)

# 🔹 CSV Export
def generate_csv():
    with open("report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Attack Type", "Severity"])

        for item in report_data:
            parts = item.split(" → ")
            ip = parts[0]
            rest = parts[1].split(" (")
            attack = rest[0]
            severity = rest[1].replace(")", "")

            writer.writerow([ip, attack, severity])

# 🔹 Main Dashboard
@app.route('/', methods=['GET', 'POST'])
def home():
    html = """
    <html>
    <head>
    <style>
    body {
        background-color: #121212;
        color: #e0e0e0;
        font-family: Arial;
    }
    h1 { color: #00ffcc; }
    h2 { color: #ffcc00; }
    ul {
        background-color: #1e1e1e;
        padding: 10px;
        border-radius: 8px;
    }
    a { color: #00ffcc; }
    input[type=submit] {
        background-color: #00ffcc;
        border: none;
        padding: 10px;
        cursor: pointer;
    }
    </style>
    </head>
    <body>

    <h1>DFIR Log Analyzer Dashboard</h1>
    """

    if request.method == 'POST':
        file = request.files['logfile']
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        top_ips, suspicious_ips = analyze_log(filepath)

        generate_graph(top_ips)
        generate_pdf()
        generate_csv()

        html += "<h2>Top IP Addresses</h2><ul>"
        for ip, count in top_ips:
            html += f"<li>{ip} - {count} requests</li>"
        html += "</ul>"

        html += "<h2 style='color:red;'>Suspicious IPs (404 Errors)</h2><ul>"
        for ip, count in suspicious_ips:
            html += f"<li>{ip} - {count} failed requests</li>"
        html += "</ul>"

        html += "<h2>Detected Attacks</h2><ul>"
        for item in report_data:
            html += f"<li>{item}</li>"
        html += "</ul>"

        html += "<h2>IP Activity Graph</h2>"
        html += "<img src='/static/graph.png' width='500'>"

        html += "<br><br><a href='/download_pdf'>Download PDF Report</a>"
        html += "<br><a href='/download_csv'>Download CSV Report</a>"

    html += """
    <h2>Upload Log File</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="logfile">
        <input type="submit" value="Analyze">
    </form>

    <br><a href="/live">Live Apache Monitoring</a>

    </body>
    </html>
    """

    return html

# 🔹 PDF Download
@app.route('/download_pdf')
def download_pdf():
    return send_file("report.pdf", as_attachment=True)

# 🔹 CSV Download
@app.route('/download_csv')
def download_csv():
    return send_file("report.csv", as_attachment=True)

# 🔹 Live Monitoring
@app.route('/live')
def live():
    filepath = "/var/log/apache2/access.log"

    if not os.path.exists(filepath):
        return "Apache log not found"

    top_ips, suspicious_ips = analyze_log(filepath)
    generate_graph(top_ips)

    html = "<h1>Live Apache Monitoring</h1>"

    html += "<h2>Top IPs</h2><ul>"
    for ip, count in top_ips:
        html += f"<li>{ip} - {count}</li>"
    html += "</ul>"

    html += "<h2 style='color:red;'>Suspicious</h2><ul>"
    for ip, count in suspicious_ips:
        html += f"<li>{ip} - {count}</li>"
    html += "</ul>"

    html += "<img src='/static/graph.png' width='500'>"
    html += "<br><a href='/live'>Refresh</a>"

    return html

# 🔹 Run App
if __name__ == '__main__':
    app.run(debug=True)
