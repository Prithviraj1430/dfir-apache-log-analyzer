# 🔍 DFIR Apache Log Analyzer

A Digital Forensic Incident Response (DFIR) tool for analyzing Apache web server logs to detect malicious activities such as brute force attacks, SQL injection, directory traversal, and abnormal traffic patterns.

---

## 🚀 Project Overview

This project focuses on forensic analysis of Apache access logs to identify suspicious behavior and reconstruct potential cyber attack patterns. It provides an automated and user-friendly dashboard for log analysis, visualization, and report generation.

---

## 🛠️ Features

* 🔎 Log File Analysis (Apache Access Logs)
* 🚨 Attack Detection:

  * Brute Force Attacks
  * SQL Injection
  * Directory Traversal
  * Admin Panel Scanning
* ⚠️ Severity Classification (Low / Medium / High)
* 📊 Graph Visualization of IP Activity
* 📄 PDF Report Generation
* 📁 CSV Export of Analysis
* 🌐 Web Dashboard (Flask-based UI)
* 📤 Log File Upload Support
* 🔄 On-Demand Log Monitoring

---

## 🧪 Technologies Used

* Python
* Flask (Web Framework)
* Matplotlib (Visualization)
* ReportLab (PDF Generation)
* Linux / Ubuntu
* Apache Web Server Logs

---

## 📂 Project Structure

```
dfir-log-analysis/
│── app.py
│── analyzer.py
│── access.log
│── uploads/
│── static/
│── report.pdf
│── report.csv
│── venv/
│── README.md
```

---

## ▶️ How to Run

### 1. Clone Repository

```bash
git clone https://github.com/Prithviraj1430/dfir-apache-log-analyzer.git
cd dfir-apache-log-analyzer
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install flask matplotlib reportlab
```

### 4. Run Application

```bash
python app.py
```

### 5. Open in Browser

```
http://127.0.0.1:5000
```

---

## 📊 How It Works

1. Upload Apache access log file
2. System parses log entries
3. Detects malicious patterns using rule-based analysis
4. Classifies attacks and assigns severity levels
5. Displays results in dashboard with graph
6. Generates downloadable PDF and CSV reports

---

## 🧠 Key Concepts

* Digital Forensics
* Log Analysis
* Pattern-Based Attack Detection
* Incident Response
* Data Visualization

---

## 🎯 Sample Attacks Detected

* Multiple failed login attempts → Brute Force
* Access to `/admin` → Unauthorized scanning
* `../` patterns → Directory traversal
* SQL keywords → Injection attempts
* High request frequency → DoS behavior

---

## 👨‍💻 Author

**Prithviraj**
Cyber Security Student

---

## ⭐ Future Enhancements

* Real-time log monitoring
* Machine learning-based anomaly detection
* Alert system for suspicious activities
* Advanced dashboard UI

---

## 📌 Conclusion

This project demonstrates a practical approach to digital forensic analysis of web server logs using automation and visualization techniques. It helps in identifying malicious activities and supports incident response workflows.

---
