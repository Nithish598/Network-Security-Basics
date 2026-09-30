# NETWORK SECURITY BASICS – NETWORK SECURITY ANALYZER

> **An Interactive Academic Cyber Defense & Security Assessment Dashboard**  
> *Developed for College Academic Demonstrations, Lab Projects, and Viva Voce Examinations.*

---

## 1. Introduction

In modern computing environments, understanding fundamental network security concepts is essential for developers, system administrators, and cybersecurity students. The **Network Security Analyzer** is an educational, interactive web application built with Python and Streamlit. It provides a visual Security Operations Center (SOC) dashboard that demonstrates how core network parameters—such as perimeter firewalls, transmission encryption (HTTPS), administrative password complexity, open port configurations, and device discovery—directly influence the security posture of an organization.

The project is designed to bridge the gap between theoretical computer networking concepts and practical defense-in-depth methodologies without exposing systems or networks to harm.

---

## 2. Problem Statement

Many academic curricula teach cybersecurity and networking through abstract command-line tools or theoretical textbooks. However:
1. **Lack of Visual Feedback**: Students often struggle to visualize the cumulative impact of configuration weaknesses (e.g., how an open Telnet port combined with a disabled firewall elevates network risk).
2. **Risks of Real-World Scanning**: Demonstrating real vulnerability scanners (like Nmap, Nessus, or Metasploit) on campus or shared networks can trigger Intrusion Detection Systems (IDS), disrupt services, or violate institutional Acceptable Use Policies (AUP).
3. **Complexity of Setup**: Enterprise security dashboards and SIEM platforms (such as Splunk or Elastic Security) require substantial computing resources, database administration, and intricate licensing.

There is a clear need for a lightweight, self-contained, and completely safe educational simulation tool that can demonstrate risk assessment, threat identification, and remediation workflows on standard laptops during academic examinations.

---

## 3. Objectives

The primary objectives of the **Network Security Analyzer** are:
* **Demonstrate Core Concepts**: Provide clear, interactive demonstrations of firewalls, transport-layer encryption (SSL/TLS), password entropy, port exposures, and defensive HTTP headers.
* **Transparent Risk Scoring**: Implement a transparent, rule-based mathematical scoring engine (0–100 scale) that students can explain step-by-step during a viva voce.
* **Safe Educational Simulation**: Ensure 100% safety with zero intrusive packet transmission, port scanning, brute-forcing, or external network probing.
* **Executive Security Reporting**: Automatically generate downloadable security audit reports in `.txt` and `.csv` formats based on active telemetry.
* **Demystify Common Threats**: Provide an educational threat intelligence hub detailing malware, phishing, MitM, DoS/DDoS, credential attacks, and rogue Wi-Fi networks along with the CIA Triad.

---

## 4. Proposed System

The proposed system is an agentic, single-page reactive web application featuring:
* **Cybersecurity Aesthetics**: Dark navy/blue background (`#0b1120`), glowing cyan accents (`#06b6d4`), responsive metric tiles, and standard alert colors (Green = Secure, Yellow/Orange = Warning, Red = High Risk).
* **Multi-Module Navigation**: An 8-page sidebar allowing users to jump seamlessly between high-level SOC metrics, detailed configuration assessments, password evaluation, port audits, web posture checks, threat education, audit reporting, and project metadata.
* **In-Memory State Management**: Utilizing Streamlit's reactive `session_state` to propagate configuration changes across all pages instantly without requiring an external database.
* **Pre-Configured Demo Profiles**: One-click presets ("College WiFi", "Cafe Hotspot", "Insecure Legacy Host") enabling instant demonstration of different security levels.

---

## 5. Technologies Used

* **Language**: Python 3.9+ (Python 3.14 compatible)
* **Web Framework**: [Streamlit](https://streamlit.io/) (High-performance reactive data application framework)
* **Data Processing**: [Pandas](https://pandas.pydata.org/) (Data structures and tabular audit logs)
* **Standard Python Libraries**:
  * `ipaddress` (RFC-compliant IPv4 address validation)
  * `re` (Regular expressions for character class and password pattern analysis)
  * `datetime` (Audit timestamping)
  * `io` (In-memory buffer streaming for CSV downloads)
* **Styling**: Responsive HTML5 & CSS3 with CSS Grid, Flexbox, and glowing cyber accents

---

## 6. System Requirements

### Hardware Requirements
* **Processor**: Intel Core i3 / AMD Ryzen 3 or higher (or equivalent ARM chip)
* **RAM**: Minimum 2 GB (4 GB recommended)
* **Storage**: Less than 100 MB free disk space

### Software Requirements
* **Operating System**: Windows 10/11, macOS, or Linux
* **Python**: Python 3.9 or higher
* **Web Browser**: Modern browser (Google Chrome, Mozilla Firefox, Microsoft Edge, Safari)

---

## 7. Modules

### Module 1 – Dashboard
* **Purpose**: Serves as the centralized Security Operations Center (SOC) console.
* **Features**:
  * 4 summary metric tiles: **Total Checks**, **Secure**, **Warnings**, and **High Risk**.
  * Large color-coded **Overall Security Score** visual gauge (0–100 scale) with status badge (`SECURE`, `MODERATE`, `WARNING`, `HIGH RISK`).
  * Telemetry overview card displaying active network name, target IP, firewall status, and port count.
  * **Recent Security Checks** interactive data table.
  * Preview of identified security findings and actionable recommendations.
  * `⚡ Run Security Assessment` button to refresh dashboard telemetry.

### Module 2 – Security Assessment
* **Purpose**: Allows users to input and evaluate custom network telemetry.
* **Inputs**:
  * **Network Name**: User-friendly identifier (e.g., `College WiFi`).
  * **IP Address**: Target IPv4 address with strict validation (rejects invalid strings).
  * **Firewall**: Radio selection (`Enabled` / `Disabled`).
  * **HTTPS**: Radio selection (`Enabled` / `Disabled`).
  * **Number of Open Ports**: Numeric stepper (0 to 65,535).
  * **Unknown Devices**: Numeric stepper (0 to 255).
  * **Administrative Password Strength**: Selectbox (`Strong`, `Medium`, `Weak`).
* **Evaluation Engine**:
  * Baseline 100 points.
  * Firewall disabled: `-25 pts`
  * HTTPS disabled: `-20 pts`
  * Weak password: `-20 pts` (Medium: `-5 pts`)
  * Open ports > 5: `-15 pts`
  * Unknown devices > 2: `-10 pts`
  * High-risk port selected: `-10 pts`
* **Outputs**: Displays security status banner, detected issue list, recommended actions, and a transparent deduction breakdown table.

### Module 3 – Password Strength
* **Purpose**: Evaluates client-side authentication credentials for educational purposes.
* **Privacy & Safety**: Processed 100% in local memory. Passwords are **never** stored, logged, or transmitted over the wire.
* **Checks**:
  * Length: 12+ characters (recommended) and 8+ characters (minimum).
  * Uppercase characters (`A–Z`).
  * Lowercase characters (`a–z`).
  * Numeric digits (`0–9`).
  * Special characters (`!@#$%^&*`).
* **Classification**:
  * 🟢 **Strong**: 12+ characters with uppercase, lowercase, numbers, and special symbols.
  * 🟡 **Medium**: 8+ characters with at least three character categories.
  * 🔴 **Weak**: Short passwords (< 8 characters), single-case letters, or lack of diversity.

### Module 4 – Port Security
* **Purpose**: Simulates open port risk analysis without conducting active network scanning.
* **Knowledge Base**:
  * **Port 21 (FTP)**: File Transfer Protocol | Medium Risk | Recommend SFTP/FTPS.
  * **Port 22 (SSH)**: Secure Shell | Low Risk | Recommend key-based auth & disable root login.
  * **Port 23 (Telnet)**: Insecure Remote Shell | High Risk | Transmits cleartext passwords; replace with SSH.
  * **Port 25 (SMTP)**: Mail Transfer | Medium Risk | Enforce TLS (587) and SPF/DKIM.
  * **Port 53 (DNS)**: Domain Name System | Low Risk | Deploy DNSSEC against cache poisoning.
  * **Port 80 (HTTP)**: Web Traffic | Medium Risk | Enforce 301 redirection to HTTPS on port 443.
  * **Port 443 (HTTPS)**: Secure Web Protocol | Low Risk | Standard encrypted transport.
  * **Port 3389 (RDP)**: Remote Desktop Protocol | High Risk | Restrict behind corporate VPN and mandate MFA.
* **Features**: Multi-select interface, dynamic port risk counters (Safe, Warning, High Risk), and detailed remediation table.

### Module 5 – Web Security
* **Purpose**: Evaluates web application transport security and HTTP protective headers.
* **Inputs**:
  * Protocol (`HTTPS` / `HTTP`)
  * SSL/TLS Certificate (`Valid` / `Invalid` / `Unknown`)
  * Security Headers (`Present` / `Missing` / `Unknown`)
* **Outputs**: Overall web security rating and educational documentation of essential headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).

### Module 6 – Threat Information
* **Purpose**: Educational threat encyclopedia explaining prominent cyber attack vectors:
  1. **Malware** (Viruses, Worms, Trojans, Ransomware)
  2. **Phishing** (Credential harvesting and deception)
  3. **Man-in-the-Middle (MitM)** (Packet eavesdropping and session hijacking)
  4. **Denial of Service (DoS / DDoS)** (Traffic overwhelming attacks)
  5. **Password Attacks** (Brute-force, dictionary, and credential stuffing)
  6. **Unsecured Wi-Fi** (Packet sniffing and rogue Evil Twin hotspots)
* Each card details **Definition**, **Common Impact**, and **Basic Prevention**.
* Includes an overview of the foundational **CIA Triad** (Confidentiality, Integrity, Availability).

### Module 7 – Security Report
* **Purpose**: Compiles active assessment parameters into an executive-level security audit report.
* **Features**:
  * Visual pre-formatted report viewer.
  * `📋 Generate Report` button.
  * `⬇️ Download Report (.txt)`: Generates an RFC-compliant plain text audit file.
  * `⬇️ Download Audit Data (.csv)`: Exports structured tabular audit findings for spreadsheet analysis.

### Module 8 – About Project
* **Purpose**: Academic documentation covering project background, core objectives, features, benefits, and ethical compliance declarations.

---

## 8. System Workflow

The application executes following this structured, linear security evaluation workflow:

```
[ User Input / Telemetry Form ]
              ↓
    [ IPv4 & Input Validation ]
              ↓
  [ Rule-Based Security Engine ]
              ↓
    [ Risk & Threat Analysis ]
              ↓
 [ Security Score & Deductions ] (0–100 Scale)
              ↓
  [ Status Classification ] (Secure / Moderate / Warning / High Risk)
              ↓
[ Actionable Remediation Guidance ]
              ↓
[ Interactive Dashboard & Exportable Reports (.txt / .csv) ]
```

---

## 9. Advantages

1. **Academic Friendly**: Tailored specifically for college lab exams, seminars, and viva voce demonstrations.
2. **Safe & Non-Destructive**: 100% simulation; produces no harmful network traffic, port scanning, or malicious activity.
3. **No External Dependencies**: Operates entirely offline without cloud APIs, subscription keys, or external databases.
4. **Transparent Scoring**: Every point deduction is calculated with clear mathematical logic that examiners can verify.
5. **Interactive & Responsive**: Instant recalculation upon modifying input values or clicking demo presets.
6. **Executive Export**: Produces real `.txt` and `.csv` audit documents suitable for submission.

---

## 10. Limitations

* **Simulated Environment**: The application is an educational simulator and does **not** conduct live packet captures, real network vulnerability scans, or automated penetration testing.
* **Input-Driven Assessment**: Scoring and findings are derived from user-supplied parameters and predefined security heuristics rather than active socket probing.
* **Single-Host / Session Scope**: Data is maintained in browser session state and does not persist across server restarts (intentionally avoiding complex database overhead).

---

## 11. Future Enhancements

Potential future extensions for an advanced Capstone or Master's level project include:
* **Authorized Live Network Probing**: Integrating `scapy` or `socket` libraries to perform authorized local ping checks in controlled lab subnets.
* **SIEM & Syslog Integration**: Streaming generated audit events to an external SIEM (e.g., Elasticsearch, Splunk, or Graylog) via Syslog protocol (RFC 5424).
* **Intrusion Detection System (IDS) Log Parser**: Adding a log parser for Snort or Suricata alert files to display real-time intrusion signatures.
* **Role-Based Access Control (RBAC)**: Multi-user authentication supporting Auditor, Administrator, and Read-Only roles.
* **Database Persistence**: Connecting to PostgreSQL or SQLite to maintain historical trend audits over months.

---

## 12. Conclusion

The **Network Security Analyzer** successfully demonstrates that critical cybersecurity principles can be taught and demonstrated effectively through an intuitive, visual, and safe web dashboard. By translating abstract configuration states into actionable scores, risk levels, and remediation steps, the application provides an ideal platform for college students to showcase their understanding of network defense, encryption, credential security, and threat mitigation during academic evaluations.

---

## 13. How to Run the Project

### Step 1: Clone or Navigate to the Project Directory
```bash
cd "c:\Users\shinc\OneDrive\Desktop\network security basics"
```

### Step 2: Install Required Dependencies
```bash
pip install -r requirements.txt
```
*(Or use `python -m pip install -r requirements.txt`)*

### Step 3: Run the Application
You can run the app using either Streamlit or npm:

**Option A (Using Streamlit / Python):**
```bash
streamlit run app.py
```
*(Or if `streamlit` is not on your PATH: `python -m streamlit run app.py`)*

**Option B (Using npm):**
```bash
npm run dev
```

### Step 4: Open in Web Browser
Open your browser and navigate to:
```
http://localhost:8501
```

---

## 14. Viva Voce Preparation Guide

### 2-Minute Viva Pitch Script
> *"Good morning, Respected Examiners. Today, I am demonstrating my academic project: the **Network Security Basics – Network Security Analyzer**.*
>
> *In computer networking, maintaining a robust security posture requires proactive assessment of perimeter controls, transport encryption, and service exposures. Our project provides an interactive, visual Security Operations Center (SOC) dashboard developed using Python, Streamlit, and Pandas.*
>
> *The application evaluates a network's security posture across seven critical parameters: perimeter firewall status, HTTPS encryption, administrative password complexity, open port exposures, unknown device counts, web headers, and common threat vectors. It utilizes a transparent, rule-based algorithm starting from a 100-point security baseline. For example, disabling the firewall deducts 25 points, unencrypted HTTP traffic deducts 20 points, and weak passwords deduct 20 points. Networks are then classified into four clear categories: Secure, Moderate, Warning, or High Risk.*
>
> *Most importantly, this project was developed under strict ethical guidelines. It operates purely as an educational simulator without conducting invasive scans, password cracking, or denial-of-service attacks, making it 100% safe for institutional networks. It also provides instant exportable security audit reports in plain text and CSV formats.*
>
> *I am now ready to demonstrate the live modules and answer your questions."*

---

### Top 10 Viva Voce Questions & Model Answers

#### Q1: What is the primary objective of this project?
**Answer**: To demonstrate fundamental network security concepts and provide a transparent, beginner-friendly simulation tool for evaluating network vulnerabilities, scoring risks, and recommending defensive countermeasures.

#### Q2: Why is the project built as a simulation rather than using active penetration testing tools?
**Answer**: Active penetration testing tools (like port scanners or exploit frameworks) can disrupt network operations, trigger security alarms, and violate institutional acceptable use policies. A simulation provides safe, predictable, and educational demonstrations of risk principles without any legal or operational hazards.

#### Q3: How does the security scoring algorithm work?
**Answer**: The algorithm starts with a clean baseline of 100 points and applies transparent deductions based on detected risks:
* Firewall disabled: `-25 points`
* HTTPS disabled: `-20 points`
* Weak password: `-20 points` (Medium: `-5 points`)
* Open ports > 5: `-15 points`
* Unknown devices > 2: `-10 points`
* High-risk port selected: `-10 points`
Scores are bounded between 0 and 100, then categorized into: Secure (80–100), Moderate (60–79), Warning (40–59), and High Risk (0–39).

#### Q4: Why is a firewall considered the most critical perimeter defense?
**Answer**: A firewall functions at Layers 3 and 4 (and Layer 7 for next-gen firewalls) to enforce packet filtering policies. Disabling it leaves internal systems directly exposed to unauthorized inbound connection requests and automated port probes from untrusted networks.

#### Q5: What is the security difference between HTTP and HTTPS?
**Answer**: HTTP transmits all request and response data in clear, unencrypted text across Port 80, allowing anyone on the network path to eavesdrop or tamper with data. HTTPS encrypts traffic using TLS (Transport Layer Security) across Port 443, ensuring confidentiality, message integrity, and server authentication.

#### Q6: Why is Telnet (Port 23) classified as a High-Risk port compared to SSH (Port 22)?
**Answer**: Telnet transmits all data—including administrative usernames and passwords—in clear plaintext. Anyone running a simple packet sniffer (like Wireshark) on the local subnet can capture the credentials. SSH encrypts the entire remote shell session using public-key cryptography and strong symmetric ciphers.

#### Q7: What makes a password "Strong" in your evaluation module?
**Answer**: In our evaluation logic, a Strong password must be at least 12 characters in length and contain a diverse mixture of uppercase letters, lowercase letters, numeric digits, and special symbols (!@#$%^&*), providing exponential mathematical resistance against offline dictionary and brute-force attacks.

#### Q8: What is the CIA Triad, and how is it reflected in your system?
**Answer**: The CIA Triad represents the three foundational pillars of information security:
1. **Confidentiality**: Ensuring data is accessible only to authorized users (implemented via HTTPS encryption and strong passwords).
2. **Integrity**: Protecting data against unauthorized modification (implemented via TLS checksums and valid digital certificates).
3. **Availability**: Ensuring timely, reliable access to network services (addressed through firewall filtering and DoS prevention).

#### Q9: How are unknown network devices a security risk?
**Answer**: Unregistered or unknown devices connected to a subnet could be rogue access points, unpatched personal devices (BYOD), or attacker machines. They may introduce malware, bypass security controls, or execute lateral network movement.

#### Q10: How does the application generate and download reports without a database?
**Answer**: The application dynamically compiles the current session state and audit findings into formatted string buffers using Python's built-in `io.StringIO` and Streamlit's `st.download_button()`. This allows users to download `.txt` and `.csv` audit files on-the-fly directly to their browser without database storage overhead.
