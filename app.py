# ==============================================================================
# NETWORK SECURITY BASICS – NETWORK SECURITY ANALYZER
# Academic Demonstration & Viva Ready Web Application
# Built with Python, Streamlit, and Pandas
# 100% Safe Simulation - No External Scanning, Exploitation, or Password Cracking
# ==============================================================================

import ipaddress
import re
import datetime
import io
import pandas as pd
import streamlit as st

# ------------------------------------------------------------------------------
# 1. HELPER FUNCTIONS & PURE SECURITY ENGINES (TESTABLE & MODULAR)
# ------------------------------------------------------------------------------
def validate_ipv4(ip_str: str):
    """Validate that the input string is a valid IPv4 address."""
    if not ip_str or not ip_str.strip():
        return False, "Please enter an IPv4 address (cannot be empty)."
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True, ""
    except ValueError:
        return False, "Please enter a valid IPv4 address."

def get_port_database():
    """Return educational knowledge base of standard simulated ports."""
    return {
        "21 – FTP": {
            "port": 21,
            "service": "FTP (File Transfer Protocol)",
            "risk": "Medium",
            "recommendation": "Prefer secure file transfer such as SFTP (Port 22) or FTPS to prevent cleartext credential sniffing."
        },
        "22 – SSH": {
            "port": 22,
            "service": "SSH (Secure Shell)",
            "risk": "Low",
            "recommendation": "Secure remote administration. Enforce public-key authentication and disable root login."
        },
        "23 – Telnet": {
            "port": 23,
            "service": "Telnet (Unencrypted Remote Shell)",
            "risk": "High",
            "recommendation": "Disable Telnet and use SSH. Telnet transmits usernames, passwords, and commands in cleartext."
        },
        "25 – SMTP": {
            "port": 25,
            "service": "SMTP (Simple Mail Transfer)",
            "risk": "Medium",
            "recommendation": "Use encrypted SMTP over TLS (Port 587 or 465) with SPF, DKIM, and DMARC to avoid spam spoofing."
        },
        "53 – DNS": {
            "port": 53,
            "service": "DNS (Domain Name System)",
            "risk": "Low",
            "recommendation": "Critical name resolution service. Ensure DNSSEC is configured to prevent DNS cache poisoning."
        },
        "80 – HTTP": {
            "port": 80,
            "service": "HTTP (Hypertext Transfer Protocol)",
            "risk": "Medium",
            "recommendation": "Enforce HTTP-to-HTTPS redirection (Port 443) and enable HSTS to prevent unencrypted web traffic."
        },
        "443 – HTTPS": {
            "port": 443,
            "service": "HTTPS (Secure Web Protocol)",
            "risk": "Low",
            "recommendation": "Keep HTTPS enabled with modern TLS 1.2/1.3 cipher suites and valid TLS certificates."
        },
        "3389 – RDP": {
            "port": 3389,
            "service": "RDP (Remote Desktop Protocol)",
            "risk": "High",
            "recommendation": "Restrict RDP access behind a corporate VPN and firewall rules; mandate Multi-Factor Authentication (MFA)."
        }
    }

def calculate_security_score(firewall, https, password_strength, open_ports, unknown_devices, high_risk_ports=False):
    """
    Transparent scoring algorithm:
    Start with 100 points
    Subtract:
    - Firewall disabled: -25
    - HTTPS disabled: -20
    - Weak password: -20
    - More than 5 open ports: -15
    - More than 2 unknown devices: -10
    - High-risk port selected: -10
    Minimum score: 0
    Classification:
    80–100 -> Secure
    60–79  -> Moderate
    40–59  -> Warning
    0–39   -> High Risk
    """
    score = 100
    deductions = []
    issues = []
    recommendations = []

    # 1. Firewall check
    if firewall == "Disabled":
        score -= 25
        deductions.append(("Firewall is disabled", -25, "Perimeter is unshielded, allowing unrestricted inbound connection attempts."))
        issues.append("⚠ Firewall is disabled")
        recommendations.append("Enable the firewall.")
    else:
        deductions.append(("Firewall is enabled", 0, "Packet filtering active at network perimeter."))

    # 2. HTTPS check
    if https == "Disabled":
        score -= 20
        deductions.append(("HTTPS is disabled", -20, "Web data is transmitted in unencrypted cleartext (HTTP)."))
        issues.append("⚠ HTTPS is not enabled")
        recommendations.append("Use HTTPS for secure communication.")
    else:
        deductions.append(("HTTPS is enabled", 0, "Data in transit is protected via TLS encryption."))

    # 3. Password Strength check
    if password_strength == "Weak":
        score -= 20
        deductions.append(("Password is weak", -20, "Vulnerable to automated dictionary and brute-force attacks."))
        issues.append("⚠ Weak authentication password detected")
        recommendations.append("Use strong passwords.")
    elif password_strength == "Medium":
        score -= 5
        deductions.append(("Password is medium", -5, "Acceptable length but lacks ideal complexity diversity."))
        issues.append("⚠ Medium password strength: consider adding more length and special symbols")
        recommendations.append("Upgrade passwords to 12+ characters with special symbols.")
    else:
        deductions.append(("Password is strong", 0, "High entropy credentials resistant to offline cracking."))

    # 4. Open Ports check
    if open_ports > 5:
        score -= 15
        deductions.append((f"More than 5 open ports ({open_ports} ports)", -15, "Large attack surface increases vulnerability to service exploits."))
        issues.append("⚠ Multiple open ports detected")
        recommendations.append("Close unnecessary ports.")
    else:
        deductions.append((f"Open ports within safe limits ({open_ports} ports)", 0, "Controlled attack surface (5 or fewer ports)."))

    # 5. Unknown Devices check
    if unknown_devices > 2:
        score -= 10
        deductions.append((f"More than 2 unknown devices ({unknown_devices} devices)", -10, "Unmanaged or rogue endpoints detected on the network segment."))
        issues.append(f"⚠ Multiple unknown devices detected ({unknown_devices} devices)")
        recommendations.append("Isolate and verify all unknown network devices.")
    elif unknown_devices > 0:
        deductions.append((f"Unknown devices ({unknown_devices} device)", 0, "Low count of unknown devices, monitoring advised."))
        recommendations.append("Audit connected endpoints using Network Access Control (NAC).")
    else:
        deductions.append(("Unknown devices: None (0 devices)", 0, "All connected devices are registered and recognized."))

    # 6. High-Risk Port check
    if high_risk_ports:
        score -= 10
        deductions.append(("High-risk simulated port selected (Telnet/RDP)", -10, "Insecure or exposed management service active."))
        issues.append("⚠ High-risk port active (e.g. Telnet or exposed RDP)")
        recommendations.append("Disable Telnet and protect remote administration ports behind a VPN.")

    # Bound score
    score = max(0, min(100, score))

    # Determine Base Classification
    if score >= 80:
        status = "Secure"
        status_color = "#10b981"
        status_badge = "badge-secure"
    elif score >= 60:
        status = "Moderate"
        status_color = "#38bdf8"
        status_badge = "badge-warning"
    elif score >= 40:
        status = "Warning"
        status_color = "#f59e0b"
        status_badge = "badge-warning"
    else:
        status = "High Risk"
        status_color = "#ef4444"
        status_badge = "badge-danger"

    # Explicit Module Rule Overrides:
    # If firewall is disabled -> High Risk
    # If password is weak -> High Risk
    # If HTTPS is disabled -> Warning (if not already High Risk)
    # If open ports > 5 -> Warning (if not already High Risk)
    # If unknown devices > 2 -> Warning (if not already High Risk)
    if firewall == "Disabled" or password_strength == "Weak":
        status = "High Risk"
        status_color = "#ef4444"
        status_badge = "badge-danger"
    elif (https == "Disabled" or open_ports > 5 or unknown_devices > 2) and status == "Secure":
        status = "Warning"
        status_color = "#f59e0b"
        status_badge = "badge-warning"

    if not issues:
        issues.append("✅ All baseline security controls are active and within safe thresholds.")
    if not recommendations:
        recommendations.append("✅ Continue following cybersecurity best practices and conduct routine audits.")

    return score, status, status_color, status_badge, issues, recommendations, deductions

def evaluate_password(pwd: str):
    """
    Evaluate password strength for educational purposes.
    Passwords are processed strictly in local browser memory and never stored or transmitted.
    """
    if not pwd:
        return "Empty", 0, "#94a3b8", [], []
    
    length_12 = len(pwd) >= 12
    length_8 = len(pwd) >= 8
    has_upper = bool(re.search(r'[A-Z]', pwd))
    has_lower = bool(re.search(r'[a-z]', pwd))
    has_number = bool(re.search(r'[0-9]', pwd))
    has_special = bool(re.search(r'[^A-Za-z0-9]', pwd))

    checklist = [
        ("At least 12 characters", length_12),
        ("At least 8 characters (minimum)", length_8),
        ("Contains uppercase letters (A–Z)", has_upper),
        ("Contains lowercase letters (a–z)", has_lower),
        ("Contains numbers (0–9)", has_number),
        ("Contains special characters (!@#$%^&*)", has_special)
    ]

    tips = []
    if not length_12:
        tips.append("Use at least 12 characters for maximum resilience against brute-force attacks.")
    if not (has_upper and has_lower):
        tips.append("Include uppercase and lowercase letters to expand the character search space.")
    if not has_number:
        tips.append("Include numbers to deter automated dictionary pattern guessing.")
    if not has_special:
        tips.append("Include special characters to defeat rainbow tables and wordlists.")
    tips.append("Avoid common passwords, personal information, or repetitive sequences.")

    # Rule Classification:
    # Strong: 12+ characters, uppercase, lowercase, number, special character
    # Medium: 8+ characters, some character variety
    # Weak: short password, only letters, common/simple pattern
    if length_12 and has_upper and has_lower and has_number and has_special:
        rating = "Strong"
        score_val = 100
        color = "#10b981"
    elif length_8 and sum([has_upper, has_lower, has_number, has_special]) >= 3:
        rating = "Medium"
        score_val = 65
        color = "#f59e0b"
    else:
        rating = "Weak"
        score_val = 30
        color = "#ef4444"

    return rating, score_val, color, checklist, tips

# ------------------------------------------------------------------------------
# 2. MAIN APPLICATION FUNCTION
# ------------------------------------------------------------------------------
def main():
    # Page Configuration & Metadata
    st.set_page_config(
        page_title="Network Security Analyzer",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Custom CSS Styling
    st.markdown("""
    <style>
        /* Dark Navy & Sleek Background */
        .stApp {
            background-color: #0b1120;
            color: #f1f5f9;
            font-family: 'Segoe UI', Roboto, -apple-system, BlinkMacSystemFont, sans-serif;
        }
        
        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background-color: #070d19 !important;
            border-right: 1px solid #1e293b;
        }
        section[data-testid="stSidebar"] hr {
            border-color: #1e293b;
        }

        /* Top Cyber Header Banner */
        .cyber-header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border: 1px solid #0284c7;
            box-shadow: 0 4px 20px rgba(2, 132, 199, 0.15);
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        .cyber-title {
            font-size: 1.85rem;
            font-weight: 700;
            color: #ffffff;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 12px;
            letter-spacing: -0.5px;
        }
        .cyber-subtitle {
            color: #94a3b8;
            font-size: 0.95rem;
            margin-top: 4px;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background-color: rgba(16, 185, 129, 0.15);
            border: 1px solid #10b981;
            color: #34d399;
            padding: 6px 16px;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 0.9rem;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.2);
        }
        .pulse-dot {
            width: 9px;
            height: 9px;
            background-color: #10b981;
            border-radius: 50%;
            box-shadow: 0 0 8px #10b981;
        }

        /* Modern Card Layouts */
        .cyber-card {
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 20px 22px;
            margin-bottom: 20px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
        }
        .cyber-card-header {
            font-size: 1.15rem;
            font-weight: 700;
            color: #38bdf8;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 8px;
        }

        /* Metric Cards */
        .metric-box {
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 10px;
            padding: 16px 18px;
            text-align: center;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .metric-box:hover {
            transform: translateY(-2px);
            border-color: #38bdf8;
        }
        .metric-title {
            font-size: 0.82rem;
            text-transform: uppercase;
            color: #94a3b8;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        .metric-num {
            font-size: 2.2rem;
            font-weight: 800;
            margin: 6px 0 0 0;
        }

        /* Colors */
        .c-secure { color: #10b981 !important; }
        .c-warning { color: #f59e0b !important; }
        .c-danger { color: #ef4444 !important; }
        .c-info { color: #38bdf8 !important; }
        .c-muted { color: #94a3b8 !important; }

        /* Custom Badges */
        .badge-secure {
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.4);
            padding: 3px 10px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }
        .badge-warning {
            background: rgba(245, 158, 11, 0.15);
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.4);
            padding: 3px 10px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }
        .badge-danger {
            background: rgba(239, 68, 68, 0.15);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.4);
            padding: 3px 10px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }

        /* Checklist Item */
        .check-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            background: #1e293b;
            border-radius: 8px;
            margin-bottom: 6px;
            font-size: 0.92rem;
        }

        /* Buttons */
        .stButton>button {
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%) !important;
            color: white !important;
            border: 1px solid #38bdf8 !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            padding: 8px 22px !important;
            box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3) !important;
            transition: all 0.2s ease !important;
        }
        .stButton>button:hover {
            background: linear-gradient(135deg, #0369a1 0%, #075985 100%) !important;
            border-color: #7dd3fc !important;
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.5) !important;
        }

        /* Code & Log Box */
        .report-box {
            background: #020617;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 16px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.88rem;
            color: #cbd5e1;
            white-space: pre-wrap;
        }
    </style>
    """, unsafe_allow_html=True)

    # Session State Initialization (Demo Mode Default)
    if "network_name" not in st.session_state:
        st.session_state.network_name = "College WiFi"
    if "ip_address" not in st.session_state:
        st.session_state.ip_address = "192.168.1.20"
    if "firewall_status" not in st.session_state:
        st.session_state.firewall_status = "Enabled"
    if "https_status" not in st.session_state:
        st.session_state.https_status = "Enabled"
    if "open_ports" not in st.session_state:
        st.session_state.open_ports = 3
    if "unknown_devices" not in st.session_state:
        st.session_state.unknown_devices = 1
    if "password_strength" not in st.session_state:
        st.session_state.password_strength = "Strong"
    if "selected_ports" not in st.session_state:
        st.session_state.selected_ports = ["22 – SSH", "80 – HTTP", "443 – HTTPS"]
    if "last_assessment_time" not in st.session_state:
        st.session_state.last_assessment_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Top Cyber Header Component
    st.markdown("""
    <div class="cyber-header">
        <div>
            <div class="cyber-title">
                <span>🔐</span> Network Security Analyzer
            </div>
            <div class="cyber-subtitle">
                Network Security Basics – Threat Detection & Security Assessment
            </div>
        </div>
        <div>
            <div class="status-badge">
                <div class="pulse-dot"></div>
                System Status: Protected
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar Navigation & Demo Presets
    st.sidebar.markdown("### 🧭 Navigation Menu")
    page = st.sidebar.radio(
        "Select Module:",
        [
            "1. Dashboard",
            "2. Security Assessment",
            "3. Password Strength",
            "4. Port Security",
            "5. Web Security",
            "6. Threat Information",
            "7. Security Report",
            "8. About Project"
        ]
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🧪 Quick Demo Profiles")
    st.sidebar.caption("Preload realistic configurations for viva demonstration:")

    col_demo1, col_demo2 = st.sidebar.columns(2)
    with col_demo1:
        if st.button("🏫 College WiFi", use_container_width=True, help="Mostly secure network profile"):
            st.session_state.network_name = "College WiFi"
            st.session_state.ip_address = "192.168.1.20"
            st.session_state.firewall_status = "Enabled"
            st.session_state.https_status = "Enabled"
            st.session_state.open_ports = 3
            st.session_state.unknown_devices = 1
            st.session_state.password_strength = "Strong"
            st.session_state.selected_ports = ["22 – SSH", "80 – HTTP", "443 – HTTPS"]
            st.session_state.last_assessment_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.rerun()

    with col_demo2:
        if st.button("☕ Cafe Hotspot", use_container_width=True, help="Moderate warning profile"):
            st.session_state.network_name = "Public Cafe Hotspot"
            st.session_state.ip_address = "10.0.0.45"
            st.session_state.firewall_status = "Enabled"
            st.session_state.https_status = "Disabled"
            st.session_state.open_ports = 6
            st.session_state.unknown_devices = 3
            st.session_state.password_strength = "Medium"
            st.session_state.selected_ports = ["21 – FTP", "80 – HTTP", "443 – HTTPS"]
            st.session_state.last_assessment_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.rerun()

    if st.sidebar.button("🚨 Insecure Legacy Host", use_container_width=True, help="High risk profile"):
        st.session_state.network_name = "Legacy Server Lab"
        st.session_state.ip_address = "172.16.0.5"
        st.session_state.firewall_status = "Disabled"
        st.session_state.https_status = "Disabled"
        st.session_state.open_ports = 8
        st.session_state.unknown_devices = 4
        st.session_state.password_strength = "Weak"
        st.session_state.selected_ports = ["21 – FTP", "23 – Telnet", "80 – HTTP", "3389 – RDP"]
        st.session_state.last_assessment_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.caption("🔒 **Safety Notice**: 100% safe, educational simulation. Zero real-world attacks or invasive scans performed.")

    # Compute current state metrics
    port_db = get_port_database()
    has_high_risk_port = any(port_db[p]["risk"] == "High" for p in st.session_state.selected_ports if p in port_db)

    current_score, current_status, current_color, current_badge, current_issues, current_recs, score_breakdown = calculate_security_score(
        st.session_state.firewall_status,
        st.session_state.https_status,
        st.session_state.password_strength,
        st.session_state.open_ports,
        st.session_state.unknown_devices,
        high_risk_ports=has_high_risk_port
    )

    # --------------------------------------------------------------------------
    # MODULE 1: DASHBOARD
    # --------------------------------------------------------------------------
    if page == "1. Dashboard":
        st.markdown("### 📊 Security Operations Center (SOC) Dashboard")
        st.caption(f"Active Monitored Network: **{st.session_state.network_name}** (`{st.session_state.ip_address}`) | Telemetry Updated: **{st.session_state.last_assessment_time}**")

        # 4 Metric Summary Cards
        col1, col2, col3, col4 = st.columns(4)
        
        total_checks = 24
        if current_status == "Secure":
            secure_checks = 18
            warn_checks = 4
            risk_checks = 2
        elif current_status == "Moderate":
            secure_checks = 15
            warn_checks = 6
            risk_checks = 3
        elif current_status == "Warning":
            secure_checks = 11
            warn_checks = 9
            risk_checks = 4
        else:  # High Risk
            secure_checks = 6
            warn_checks = 7
            risk_checks = 11

        with col1:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Total Checks</div>
                <div class="metric-num c-info">{total_checks}</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Secure</div>
                <div class="metric-num c-secure">{secure_checks}</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Warnings</div>
                <div class="metric-num c-warning">{warn_checks}</div>
            </div>
            """, unsafe_allow_html=True)
        with col4:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">High Risk</div>
                <div class="metric-num c-danger">{risk_checks}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Row 2: Overall Security Score & Status
        score_col, info_col = st.columns([1, 1])

        with score_col:
            st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-card-header">🛡️ Overall Security Score</div>
                <div style="display: flex; align-items: baseline; justify-content: space-between;">
                    <span style="font-size: 2.8rem; font-weight: 800; color: {current_color};">
                        {current_score} <span style="font-size: 1.2rem; color: #94a3b8;">/ 100</span>
                    </span>
                    <span class="{current_badge}">{current_status.upper()}</span>
                </div>
            """, unsafe_allow_html=True)
            st.progress(current_score / 100)
            st.markdown("""
                <div style="display: flex; justify-content: space-between; font-size: 0.78rem; color: #94a3b8; margin-top: 6px;">
                    <span>🔴 0–39 High Risk</span>
                    <span>🟡 40–59 Warning</span>
                    <span>🔵 60–79 Moderate</span>
                    <span>🟢 80–100 Secure</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with info_col:
            st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-card-header">🔎 Network Posture Summary</div>
                <p style="margin: 5px 0;"><strong>Network Name:</strong> {st.session_state.network_name}</p>
                <p style="margin: 5px 0;"><strong>IP Address:</strong> <code>{st.session_state.ip_address}</code></p>
                <p style="margin: 5px 0;"><strong>Firewall:</strong> {st.session_state.firewall_status}</p>
                <p style="margin: 5px 0;"><strong>HTTPS Encryption:</strong> {st.session_state.https_status}</p>
                <p style="margin: 5px 0;"><strong>Open Ports:</strong> {st.session_state.open_ports} detected</p>
                <p style="margin: 5px 0;"><strong>Administrative Password:</strong> {st.session_state.password_strength}</p>
            </div>
            """, unsafe_allow_html=True)

        # Run Assessment Button
        btn_c1, btn_c2 = st.columns([1, 3])
        with btn_c1:
            if st.button("⚡ Run Security Assessment", use_container_width=True):
                st.session_state.last_assessment_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.success("✅ Dashboard assessment updated with latest simulated telemetry!")
                st.rerun()

        # Recent Security Checks Table
        st.markdown("### 📋 Recent Security Checks")
        recent_checks_data = [
            {"Check": "HTTPS Enabled", "Status": "Secure" if st.session_state.https_status == "Enabled" else "Warning", "Severity": "Low" if st.session_state.https_status == "Enabled" else "Medium"},
            {"Check": "Password Strength", "Status": "Secure" if st.session_state.password_strength == "Strong" else ("Warning" if st.session_state.password_strength == "Medium" else "High Risk"), "Severity": "Low" if st.session_state.password_strength == "Strong" else ("Medium" if st.session_state.password_strength == "Medium" else "High")},
            {"Check": "Port 22", "Status": "Secure" if "22 – SSH" in st.session_state.selected_ports else "Warning", "Severity": "Low" if "22 – SSH" in st.session_state.selected_ports else "Medium"},
            {"Check": "Firewall Status", "Status": "Secure" if st.session_state.firewall_status == "Enabled" else "High Risk", "Severity": "Low" if st.session_state.firewall_status == "Enabled" else "High"},
            {"Check": "Unknown IP", "Status": "Secure" if st.session_state.unknown_devices <= 2 else "Warning", "Severity": "Low" if st.session_state.unknown_devices <= 2 else "Medium"}
        ]
        df_recent = pd.DataFrame(recent_checks_data)
        st.dataframe(df_recent, use_container_width=True, hide_index=True)

        # Findings and Recommendations Columns
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            st.markdown("""
            <div class="cyber-card">
                <div class="cyber-card-header">⚠️ Security Findings</div>
            """, unsafe_allow_html=True)
            for issue in current_issues:
                st.markdown(f"<div style='margin-bottom: 6px; font-size: 0.92rem;'>{issue}</div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with f_col2:
            st.markdown("""
            <div class="cyber-card">
                <div class="cyber-card-header">🛡️ Recommendations</div>
            """, unsafe_allow_html=True)
            for rec in current_recs:
                st.markdown(f"<div style='margin-bottom: 6px; font-size: 0.92rem;'>• {rec}</div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # MODULE 2: SECURITY ASSESSMENT
    # --------------------------------------------------------------------------
    elif page == "2. Security Assessment":
        st.markdown("### 🛡️ Network Security Assessment Module")
        st.caption("Provide baseline network parameters to perform a rule-based simulated security assessment.")

        with st.form("security_assessment_form"):
            f_col1, f_col2 = st.columns(2)
            with f_col1:
                net_name_val = st.text_input("Network Name:", value=st.session_state.network_name)
                ip_val = st.text_input("IP Address:", value=st.session_state.ip_address, help="Example: 192.168.1.10")
                firewall_val = st.radio("Firewall:", ["Enabled", "Disabled"], index=0 if st.session_state.firewall_status == "Enabled" else 1, horizontal=True)
                https_val = st.radio("HTTPS:", ["Enabled", "Disabled"], index=0 if st.session_state.https_status == "Enabled" else 1, horizontal=True)

            with f_col2:
                open_ports_val = st.number_input("Number of Open Ports:", min_value=0, max_value=65535, value=int(st.session_state.open_ports), step=1)
                unknown_dev_val = st.number_input("Unknown Devices:", min_value=0, max_value=255, value=int(st.session_state.unknown_devices), step=1)
                pwd_val = st.selectbox("Password Strength:", ["Strong", "Medium", "Weak"], index=["Strong", "Medium", "Weak"].index(st.session_state.password_strength))

            analyze_btn = st.form_submit_button("🔍 Analyze Network", use_container_width=True)

        if analyze_btn:
            is_valid, err_msg = validate_ipv4(ip_val)
            if not is_valid:
                st.error(f"🚨 {err_msg}")
            else:
                st.session_state.network_name = net_name_val.strip() if net_name_val.strip() else "Unnamed Network"
                st.session_state.ip_address = ip_val.strip()
                st.session_state.firewall_status = firewall_val
                st.session_state.https_status = https_val
                st.session_state.open_ports = open_ports_val
                st.session_state.unknown_devices = unknown_dev_val
                st.session_state.password_strength = pwd_val
                st.session_state.last_assessment_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.success("✅ Network telemetry analyzed and updated successfully!")
                st.rerun()

        # Display Assessment Results
        st.markdown("---")
        st.markdown("### 📑 Security Assessment Result")

        res_c1, res_c2 = st.columns([1, 2])
        with res_c1:
            st.markdown(f"""
            <div class="cyber-card" style="text-align: center;">
                <div class="cyber-card-header" style="justify-content: center;">Assessment Summary</div>
                <div style="margin: 18px 0;">
                    <span class="{current_badge}" style="font-size: 1.15rem; padding: 6px 20px;">
                        SECURITY STATUS: {current_status.upper()}
                    </span>
                </div>
                <div style="font-size: 2.8rem; font-weight: 800; color: {current_color};">
                    {current_score} <span style="font-size: 1.1rem; color: #94a3b8;">/ 100</span>
                </div>
                <p style="color: #94a3b8; font-size: 0.85rem; margin-top: 6px;">Evaluation based on standard academic scoring rules.</p>
            </div>
            """, unsafe_allow_html=True)

        with res_c2:
            st.markdown("""
            <div class="cyber-card">
                <div class="cyber-card-header">⚠️ Detected Issues</div>
            """, unsafe_allow_html=True)
            for issue in current_issues:
                st.markdown(f"<p style='margin: 6px 0; font-size: 0.95rem;'>{issue}</p>", unsafe_allow_html=True)

            st.markdown("""
                <div class="cyber-card-header" style="margin-top: 18px;">💡 Security Recommendations</div>
            """, unsafe_allow_html=True)
            for rec in current_recs:
                st.markdown(f"<p style='margin: 6px 0; font-size: 0.95rem;'>• {rec}</p>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # Detailed Scoring Calculation for Viva Defense
        st.markdown("### 🧮 Score Calculation Breakdown (Viva Reference)")
        st.caption("Detailed step-by-step scoring deduction starting from a clean 100-point security baseline:")
        calc_rows = []
        for item, pts, reason in score_breakdown:
            calc_rows.append({
                "Evaluation Parameter": item,
                "Point Deduction": f"{pts} pts" if pts != 0 else "0 pts",
                "Security Impact / Rationale": reason
            })
        st.dataframe(pd.DataFrame(calc_rows), use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # MODULE 3: PASSWORD STRENGTH
    # --------------------------------------------------------------------------
    elif page == "3. Password Strength":
        st.markdown("### 🔑 Educational Password Strength Module")
        st.caption("Analyze authentication credential complexity in local browser memory. Passwords are **never** stored, transmitted, or logged.")

        pwd_input = st.text_input("Enter a sample password:", type="password", value="CollegeSecurity@2026")
        reveal_pwd = st.checkbox("👁️ Show password text")
        if reveal_pwd:
            st.info(f"Sample Password: `{pwd_input}`")

        rating, score_val, color, checklist, tips = evaluate_password(pwd_input)

        pw_col1, pw_col2 = st.columns([1, 1])

        with pw_col1:
            st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-card-header">Password Strength Result</div>
                <div style="display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 12px;">
                    <span style="font-size: 2rem; font-weight: 800; color: {color};">
                        {"🟢 Strong" if rating == "Strong" else ("🟡 Medium" if rating == "Medium" else "🔴 Weak")}
                    </span>
                    <span style="font-size: 1.2rem; font-weight: 600; color: #94a3b8;">{score_val} / 100</span>
                </div>
            """, unsafe_allow_html=True)
            st.progress(score_val / 100)
            st.markdown("""
                <p style="font-size: 0.85rem; color: #94a3b8; margin-top: 10px;">
                    Robust credentials protect authentication gateways from automated dictionary attacks and credential stuffing.
                </p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("#### 📋 Complexity Requirements Checklist")
            for label, met in checklist:
                icon = "✅" if met else "❌"
                cls = "c-secure" if met else "c-danger"
                st.markdown(f"<div class='check-item'><span>{icon}</span> <span class='{cls}'>{label}</span></div>", unsafe_allow_html=True)

        with pw_col2:
            st.markdown("""
            <div class="cyber-card">
                <div class="cyber-card-header">🛡️ Password Recommendations</div>
            """, unsafe_allow_html=True)
            for tip in tips:
                st.markdown(f"<p style='margin: 8px 0; font-size: 0.92rem;'>• {tip}</p>", unsafe_allow_html=True)

            st.markdown("""
                <div class="cyber-card-header" style="margin-top: 18px;">💡 Rules for Secure Passwords</div>
                <ul style="font-size: 0.88rem; color: #cbd5e1; padding-left: 20px;">
                    <li><strong>Strong:</strong> 12+ characters, uppercase, lowercase, number, special character.</li>
                    <li><strong>Medium:</strong> 8+ characters, some character variety.</li>
                    <li><strong>Weak:</strong> Short password, only letters, common/simple pattern.</li>
                    <li><strong>Defense Principle:</strong> Combine length with multi-character variety or adopt passphrases.</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # MODULE 4: PORT SECURITY
    # --------------------------------------------------------------------------
    elif page == "4. Port Security":
        st.markdown("### 🔌 Educational Port Security Module")
        st.caption("Safe educational port security analyzer. Analyzes simulated open ports without sending network packets or scanning external systems.")

        port_db = get_port_database()
        available_ports = list(port_db.keys())

        selected_ports_input = st.multiselect(
            "Select Simulated Open Ports:",
            options=available_ports,
            default=st.session_state.selected_ports
        )

        btn_p1, btn_p2 = st.columns([1, 4])
        with btn_p1:
            if st.button("🔍 Analyze Ports", use_container_width=True):
                st.session_state.selected_ports = selected_ports_input
                st.success("✅ Port security assessment updated!")
                st.rerun()

        # Calculate Summary
        safe_list = [p for p in selected_ports_input if port_db[p]["risk"] == "Low"]
        warn_list = [p for p in selected_ports_input if port_db[p]["risk"] == "Medium"]
        risk_list = [p for p in selected_ports_input if port_db[p]["risk"] == "High"]

        st.markdown("#### 📊 Port Security Summary")
        ps1, ps2, ps3 = st.columns(3)
        with ps1:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Safe Ports</div>
                <div class="metric-num c-secure">{len(safe_list)}</div>
            </div>
            """, unsafe_allow_html=True)
        with ps2:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Warning Ports</div>
                <div class="metric-num c-warning">{len(warn_list)}</div>
            </div>
            """, unsafe_allow_html=True)
        with ps3:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">High-Risk Ports</div>
                <div class="metric-num c-danger">{len(risk_list)}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Detailed Port Table
        st.markdown("#### 📋 Port Analysis Table")
        if selected_ports_input:
            port_table_data = []
            for p in selected_ports_input:
                info = port_db[p]
                port_table_data.append({
                    "Port": info["port"],
                    "Service": info["service"],
                    "Risk": info["risk"],
                    "Recommendation": info["recommendation"]
                })
            st.dataframe(pd.DataFrame(port_table_data), use_container_width=True, hide_index=True)
        else:
            st.info("No open ports currently selected. Select one or more simulated ports above.")

        # Educational Reference of Common Ports
        with st.expander("📚 Reference Table of Common Network Ports"):
            all_port_data = []
            for k, v in port_db.items():
                all_port_data.append({
                    "Port": v["port"],
                    "Service": v["service"],
                    "Risk": v["risk"],
                    "Recommendation": v["recommendation"]
                })
            st.dataframe(pd.DataFrame(all_port_data), use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # MODULE 5: WEB SECURITY
    # --------------------------------------------------------------------------
    elif page == "5. Web Security":
        st.markdown("### 🌐 Web Security Module")
        st.caption("Evaluate website security configuration using user-provided transport and header parameters.")

        w_col1, w_col2, w_col3 = st.columns(3)
        with w_col1:
            protocol_input = st.selectbox("Website Protocol:", ["HTTPS", "HTTP"], index=0)
        with w_col2:
            ssl_input = st.selectbox("SSL/TLS Certificate:", ["Valid", "Invalid", "Unknown"], index=0)
        with w_col3:
            headers_input = st.selectbox("Security Headers:", ["Present", "Missing", "Unknown"], index=0)

        # Analyze Web Security
        if protocol_input == "HTTPS" and ssl_input == "Valid" and headers_input == "Present":
            web_eval = "Good"
            web_icon = "🟢"
            web_color = "#10b981"
            web_badge = "badge-secure"
            web_desc = "The website adheres to modern secure transport standards with active TLS encryption and defensive HTTP headers."
        elif protocol_input == "HTTP" or ssl_input == "Invalid":
            web_eval = "Risk"
            web_icon = "🔴"
            web_color = "#ef4444"
            web_badge = "badge-danger"
            web_desc = "High security risk! Unencrypted HTTP communication or invalid certificates expose traffic to eavesdropping and data tampering."
        else:
            web_eval = "Warning"
            web_icon = "🟡"
            web_color = "#f59e0b"
            web_badge = "badge-warning"
            web_desc = "Moderate security posture. Encryption is in place, but missing security headers or unverified certificates create exposure."

        st.markdown(f"""
        <div class="cyber-card" style="margin-top: 15px;">
            <div class="cyber-card-header">Website Security Analysis</div>
            <div style="font-size: 2rem; font-weight: 800; color: {web_color};">
                {web_icon} Website Security: {web_eval}
            </div>
            <p style="margin-top: 8px; font-size: 0.95rem; color: #cbd5e1;">{web_desc}</p>
        </div>
        """, unsafe_allow_html=True)

        # Recommendations
        st.markdown("#### 🛡️ Recommendations")
        st.markdown("""
        <div class="cyber-card">
            <ul style="font-size: 0.95rem; color: #cbd5e1; padding-left: 20px; margin: 0;">
                <li style="margin-bottom: 8px;"><strong>Use HTTPS:</strong> Always encrypt web traffic to ensure confidentiality and integrity of user sessions.</li>
                <li style="margin-bottom: 8px;"><strong>Maintain a valid TLS certificate:</strong> Obtain certificates from trusted Certificate Authorities (CAs) and monitor renewal dates.</li>
                <li style="margin-bottom: 8px;"><strong>Configure appropriate security headers:</strong> Implement HSTS, Content-Security-Policy (CSP), and X-Frame-Options to prevent Clickjacking and XSS.</li>
                <li><strong>Avoid transmitting sensitive data over HTTP:</strong> Plaintext transmission exposes authentication tokens, passwords, and personal details.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # MODULE 6: THREAT INFORMATION
    # --------------------------------------------------------------------------
    elif page == "6. Threat Information":
        st.markdown("### ⚠️ Threat Information Module")
        st.caption("Educational overview of fundamental network and application security threats, their real-world impact, and defensive prevention.")

        threat_cards = [
            {
                "title": "Malware",
                "icon": "🦠",
                "definition": "Malicious software designed to damage systems, disrupt operations, or steal information (e.g. Viruses, Worms, Trojans, Ransomware).",
                "impact": "Data destruction, file encryption for ransom, system instability, unauthorized remote administrative access.",
                "prevention": "Install reputable antivirus/EDR software, apply regular system patches, restrict root/admin privileges, and never run untrusted attachments."
            },
            {
                "title": "Phishing",
                "icon": "🎣",
                "definition": "Fraudulent messages or websites designed to trick users into revealing sensitive credentials, financial details, or personal data.",
                "impact": "Unauthorized account takeover, identity theft, fraudulent monetary transfers, corporate network penetration.",
                "prevention": "Verify email sender headers and domains, deploy email authentication (SPF, DKIM, DMARC), mandate MFA, and educate users."
            },
            {
                "title": "Man-in-the-Middle Attack",
                "icon": "👥",
                "definition": "An attacker attempts to intercept, eavesdrop, or alter communication between two communicating parties without their knowledge.",
                "impact": "Session hijacking, interception of plaintext passwords, credit card theft, unauthorized injection of malicious payloads.",
                "prevention": "Enforce end-to-end encryption with HTTPS/TLS, configure HSTS, avoid untrusted public Wi-Fi without VPN, and verify SSL certificates."
            },
            {
                "title": "Denial of Service",
                "icon": "🛑",
                "definition": "An attempt to make a service or network resource unavailable to legitimate users by overwhelming it with excessive traffic or malicious requests.",
                "impact": "Critical service downtime, financial losses, loss of user trust, degraded server responsiveness.",
                "prevention": "Implement traffic rate limiting, configure firewalls with SYN flood protection, deploy CDN caching, and utilize DDoS mitigation scrubbers."
            },
            {
                "title": "Password Attacks",
                "icon": "🔑",
                "definition": "Attempts to obtain or guess authentication credentials using brute-force, dictionary attacks, rainbow tables, or credential stuffing.",
                "impact": "Unauthorized system access, privilege escalation, lateral network movement, exposure of private records.",
                "prevention": "Enforce account lockouts after consecutive failed logins, implement CAPTCHA, mandate 12+ character passphrases, and enforce MFA."
            },
            {
                "title": "Unsecured Wi-Fi",
                "icon": "📶",
                "definition": "Poorly secured or open wireless networks operating without encryption, exposing transmitted packets to nearby eavesdroppers.",
                "impact": "Unencrypted packet sniffing, transmission of credentials in cleartext, rogue access point (Evil Twin) attacks.",
                "prevention": "Mandate WPA3 or WPA2-Enterprise encryption, isolate guest networks, avoid open hotspots for sensitive transactions, and use a secure VPN."
            }
        ]

        t_c1, t_c2 = st.columns(2)
        for idx, threat in enumerate(threat_cards):
            col = t_c1 if idx % 2 == 0 else t_c2
            with col:
                st.markdown(f"""
                <div class="cyber-card">
                    <div class="cyber-card-header">{threat['icon']} {threat['title']}</div>
                    <p style="margin: 6px 0;"><strong>Definition:</strong> {threat['definition']}</p>
                    <p style="margin: 6px 0;"><strong>Common Impact:</strong> {threat['impact']}</p>
                    <p style="margin: 6px 0;"><strong>Basic Prevention:</strong> {threat['prevention']}</p>
                </div>
                """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # MODULE 7: SECURITY REPORT
    # --------------------------------------------------------------------------
    elif page == "7. Security Report":
        st.markdown("### 📑 Security Report Module")
        st.caption("Generate an executive network security assessment report and export it as a clean text or CSV file.")

        # Format Text Report
        formatted_report = f"""================================================================================
NETWORK SECURITY ANALYZER – SECURITY ASSESSMENT REPORT
================================================================================
Generated Date & Time : {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Network Name          : {st.session_state.network_name}
IP Address            : {st.session_state.ip_address}
Overall Security Score: {current_score} / 100
Security Status       : {current_status.upper()}
================================================================================

1. TELEMETRY DETAILS
--------------------------------------------------------------------------------
* Firewall Status     : {st.session_state.firewall_status}
* HTTPS Web Protocol  : {st.session_state.https_status}
* Open Ports Detected : {st.session_state.open_ports}
* Unknown Devices     : {st.session_state.unknown_devices}
* Password Strength   : {st.session_state.password_strength}
* Monitored Ports     : {', '.join(st.session_state.selected_ports)}

2. FINDINGS
--------------------------------------------------------------------------------
"""
        for idx, issue in enumerate(current_issues, start=1):
            formatted_report += f"[{idx}] {issue}\n"

        formatted_report += """
3. RECOMMENDATIONS
--------------------------------------------------------------------------------
"""
        for idx, rec in enumerate(current_recs, start=1):
            formatted_report += f"[{idx}] {rec}\n"

        formatted_report += """
4. SCORING BREAKDOWN
--------------------------------------------------------------------------------
"""
        for item, pts, reason in score_breakdown:
            formatted_report += f"- {item} ({pts} pts): {reason}\n"

        formatted_report += """================================================================================
NOTICE: This report is produced by Network Security Analyzer for academic
demonstration purposes. No intrusive network penetration testing was conducted.
================================================================================
"""

        st.markdown("#### 📄 Network Security Report Preview")
        st.text_area("Report Content:", value=formatted_report, height=360)

        # Action Buttons
        r_btn1, r_btn2, r_btn3 = st.columns([1, 1, 2])

        with r_btn1:
            if st.button("📋 Generate Report", use_container_width=True):
                st.session_state.last_assessment_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.success("✅ Report generated with up-to-date telemetry!")

        with r_btn2:
            st.download_button(
                label="⬇️ Download Report (.txt)",
                data=formatted_report,
                file_name=f"security_report_{st.session_state.network_name.lower().replace(' ', '_')}.txt",
                mime="text/plain",
                use_container_width=True
            )

        # CSV Export format
        csv_rows = [
            {"Section": "Metadata", "Field": "Network Name", "Detail": st.session_state.network_name},
            {"Section": "Metadata", "Field": "IP Address", "Detail": st.session_state.ip_address},
            {"Section": "Metadata", "Field": "Overall Security Score", "Detail": f"{current_score}/100"},
            {"Section": "Metadata", "Field": "Security Status", "Detail": current_status},
            {"Section": "Metadata", "Field": "Firewall", "Detail": st.session_state.firewall_status},
            {"Section": "Metadata", "Field": "HTTPS", "Detail": st.session_state.https_status},
            {"Section": "Metadata", "Field": "Open Ports", "Detail": st.session_state.open_ports},
            {"Section": "Metadata", "Field": "Unknown Devices", "Detail": st.session_state.unknown_devices},
            {"Section": "Metadata", "Field": "Password Strength", "Detail": st.session_state.password_strength},
        ]
        for idx, iss in enumerate(current_issues, start=1):
            csv_rows.append({"Section": "Finding", "Field": f"Finding #{idx}", "Detail": iss})
        for idx, rec in enumerate(current_recs, start=1):
            csv_rows.append({"Section": "Recommendation", "Field": f"Recommendation #{idx}", "Detail": rec})

        csv_buffer = io.StringIO()
        pd.DataFrame(csv_rows).to_csv(csv_buffer, index=False)
        csv_data = csv_buffer.getvalue()

        with r_btn3:
            st.download_button(
                label="⬇️ Download Audit Data (.csv)",
                data=csv_data,
                file_name=f"security_report_{st.session_state.network_name.lower().replace(' ', '_')}.csv",
                mime="text/csv",
                use_container_width=True
            )

    # --------------------------------------------------------------------------
    # MODULE 8: ABOUT PROJECT
    # --------------------------------------------------------------------------
    elif page == "8. About Project":
        st.markdown("### ℹ️ About Project")
        
        st.markdown("""
        <div class="cyber-card">
            <div class="cyber-card-header">📌 Project Title</div>
            <p style="font-size: 1.15rem; font-weight: 700; color: #38bdf8; margin: 0 0 4px 0;">
                Network Security Basics – Network Security Analyzer
            </p>
            <p style="color: #94a3b8; font-size: 0.95rem; margin: 0;">
                A clean, educational cybersecurity dashboard built for college academic demonstrations and viva examinations.
            </p>
        </div>
        """, unsafe_allow_html=True)

        ab_c1, ab_c2 = st.columns(2)
        with ab_c1:
            st.markdown("""
            <div class="cyber-card">
                <div class="cyber-card-header">🎯 Project Objective</div>
                <p style="font-size: 0.92rem; color: #cbd5e1; line-height: 1.6;">
                    The objective of this project is to demonstrate fundamental network security concepts and provide a simple educational tool for identifying common security risks. It enables students and evaluators to observe the direct security impact of network configurations, passwords, open ports, and web protocols in an intuitive visual interface.
                </p>
                <div class="cyber-card-header" style="margin-top: 18px;">🌟 Key Features</div>
                <ul style="font-size: 0.9rem; color: #cbd5e1; padding-left: 20px; line-height: 1.6;">
                    <li><strong>Network security assessment:</strong> Rule-based simulated risk evaluation.</li>
                    <li><strong>Password strength analysis:</strong> Local client-side entropy and complexity checker.</li>
                    <li><strong>Port security analysis:</strong> Educational evaluation of standard network ports.</li>
                    <li><strong>Web security assessment:</strong> Heuristic analysis of HTTPS and HTTP headers.</li>
                    <li><strong>Threat awareness:</strong> Comprehensive defense-in-depth knowledge base.</li>
                    <li><strong>Security recommendations:</strong> Actionable remediation guidance.</li>
                    <li><strong>Security report generation:</strong> Exportable reports in .txt and .csv formats.</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

        with ab_c2:
            st.markdown("""
            <div class="cyber-card">
                <div class="cyber-card-header">✨ Benefits</div>
                <ul style="font-size: 0.9rem; color: #cbd5e1; padding-left: 20px; line-height: 1.6;">
                    <li><strong>Easy to understand:</strong> Straightforward metrics and clear risk levels.</li>
                    <li><strong>Beginner-friendly:</strong> Designed specifically for foundational academic study.</li>
                    <li><strong>Interactive:</strong> Real-time recalculation of scores and security statuses.</li>
                    <li><strong>Educational:</strong> Highlights defensive principles and the CIA triad.</li>
                    <li><strong>Safe simulated analysis:</strong> Zero risk of damaging systems or running malicious code.</li>
                    <li><strong>No external security scanning:</strong> Operates entirely without network probes or API dependencies.</li>
                </ul>
                <div class="cyber-card-header" style="margin-top: 18px;">🛡️ Ethical & Academic Safety Compliance</div>
                <p style="font-size: 0.88rem; color: #94a3b8; line-height: 1.5;">
                    This project strictly adheres to academic computer ethics. It does not perform real-world attacks, password cracking, credential theft, exploit execution, network flooding, or unauthorized port scanning.
                </p>
            </div>
            """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
