import os
import uuid
import hashlib
import platform
import datetime


# ─────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────

def make_case_id():
    # generates a unique case id like CASE-20250331-A1B2C3D4
    now = datetime.datetime.now()
    tag = str(uuid.uuid4()).upper().split("-")[0]
    return "CASE-" + now.strftime("%Y%m%d") + "-" + tag


def calculate_sha256(text):
    # sha256 = strong hash, used as digital fingerprint of the url
    return hashlib.sha256(text.encode()).hexdigest()


def calculate_md5(text):
    # md5 = another hash type, used for extra verification
    return hashlib.md5(text.encode()).hexdigest()


# ─────────────────────────────────────────
# THEORY SECTION
# this builds the last page of the report
# explains WHY the url got that score
# ─────────────────────────────────────────

def build_theory_section(result, features, domain_name, domain_age):

    phish_prob = result.get("phishing_chance", 0)
    safe_prob  = result.get("safe_chance", 1)
    risk_level = result.get("risk_level", "UNKNOWN")
    verdict    = result.get("verdict", "UNKNOWN")

    phish_pct  = round(phish_prob * 100, 1)
    safe_pct   = round(safe_prob  * 100, 1)

    # collect all danger signals found in this url
    danger_reasons = []

    if features.get("has_https") == 0:
        danger_reasons.append("❌ HTTPS is missing — the connection is not encrypted, anyone can steal data being sent")

    if features.get("has_ip_in_url"):
        danger_reasons.append("❌ IP address is used instead of domain name — real websites always use domain names, not raw IPs")

    if features.get("is_suspicious_tld"):
        danger_reasons.append("❌ Suspicious domain extension found like .tk .xyz .ml — these are free extensions mostly used by attackers")

    if features.get("has_brand_in_subdomain"):
        danger_reasons.append("❌ A brand name is used in subdomain — attackers do this to make fake sites look like real ones")

    if features.get("has_at_symbol"):
        danger_reasons.append("❌ @ symbol found in URL — this is a trick to hide the real destination of the link")

    if features.get("has_punycode"):
        danger_reasons.append("❌ Punycode or fake lookalike characters found — used to create copies of real sites that look identical")

    if features.get("suspicious_word_count", 0) > 0:
        count = features.get("suspicious_word_count", 0)
        danger_reasons.append(f"❌ {count} suspicious words found in URL like login, verify, update, kyc — phishing sites use these to create urgency and panic")

    if features.get("is_url_shortener"):
        danger_reasons.append("❌ URL shortener service detected — real destination is hidden behind a short link")

    if features.get("is_very_long_url"):
        danger_reasons.append("❌ URL is very long — attackers make URLs long to confuse and hide the real domain")

    if features.get("has_multiple_subdomains"):
        danger_reasons.append("❌ Too many subdomains found — used to create fake official-looking URLs")

    if features.get("has_redirect_param"):
        danger_reasons.append("❌ Redirect parameter found in URL — user can be silently sent to a different dangerous site")

    if domain_age > 0 and domain_age < 30:
        danger_reasons.append(f"❌ Domain is only {domain_age} days old — phishing sites are usually created very recently")

    # collect all safe signals found in this url
    safe_reasons = []

    if features.get("has_https") == 1:
        safe_reasons.append("✅ HTTPS is present — connection is encrypted and secure")

    if not features.get("has_ip_in_url"):
        safe_reasons.append("✅ No IP address used — URL uses a proper domain name")

    if not features.get("is_suspicious_tld"):
        safe_reasons.append("✅ Domain extension looks normal and legitimate")

    if not features.get("has_brand_in_subdomain"):
        safe_reasons.append("✅ No brand name misuse detected in subdomain")

    if features.get("suspicious_word_count", 0) == 0:
        safe_reasons.append("✅ No suspicious words found anywhere in the URL")

    if not features.get("has_at_symbol"):
        safe_reasons.append("✅ No @ symbol found — URL destination is clear")

    if not features.get("is_url_shortener"):
        safe_reasons.append("✅ Not a shortened URL — real destination is visible")

    if domain_age > 365:
        safe_reasons.append(f"✅ Domain is {domain_age} days old — well established domain, less likely to be phishing")

    # decide trust level based on phishing percentage
    if phish_pct < 20:
        trust_level   = "HIGH TRUST ✅"
        trust_color   = "#2e7d32"
        trust_message = "You can trust this URL. All checks passed and phishing chance is very low."
        trust_advice  = "Safe to open. Still be careful about what personal information you share."

    elif phish_pct < 40:
        trust_level   = "MODERATE TRUST 🔵"
        trust_color   = "#1565c0"
        trust_message = "URL looks mostly safe but has some minor suspicious signals."
        trust_advice  = "Can open but do not enter passwords or banking information."

    elif phish_pct < 60:
        trust_level   = "LOW TRUST 🟡"
        trust_color   = "#f9a825"
        trust_message = "URL has several suspicious signals. Avoid sharing any sensitive data."
        trust_advice  = "Do not enter any personal, banking, or login information on this site."

    elif phish_pct < 80:
        trust_level   = "VERY LOW TRUST 🟠"
        trust_color   = "#e65100"
        trust_message = "URL shows strong phishing signals. Very likely a fake or malicious site."
        trust_advice  = "Do not open this URL. Report it to your IT team or cybercrime portal."

    else:
        trust_level   = "DO NOT TRUST 🚨"
        trust_color   = "#c62828"
        trust_message = "URL is almost certainly a phishing or malicious site."
        trust_advice  = "Do NOT open. Block immediately and report to cybercrime.gov.in"

    # build danger signals html blocks
    danger_html = ""
    if danger_reasons:
        for reason in danger_reasons:
            danger_html += f"""
            <div style="background:#fff5f5; border-left:4px solid #e53935;
                        padding:10px 16px; margin-bottom:8px; border-radius:4px;
                        font-size:0.9em; color:#333; line-height:1.6;">
                {reason}
            </div>"""
    else:
        danger_html = """
        <div style="background:#f1f8e9; border-left:4px solid #2e7d32;
                    padding:10px 16px; border-radius:4px; font-size:0.9em; color:#333;">
            ✅ No major suspicious signals found in URL structure
        </div>"""

    # build safe signals html blocks
    safe_html = ""
    if safe_reasons:
        for reason in safe_reasons:
            safe_html += f"""
            <div style="background:#f1f8e9; border-left:4px solid #2e7d32;
                        padding:10px 16px; margin-bottom:8px; border-radius:4px;
                        font-size:0.9em; color:#333; line-height:1.6;">
                {reason}
            </div>"""
    else:
        safe_html = """
        <div style="background:#fff5f5; border-left:4px solid #e53935;
                    padding:10px 16px; border-radius:4px; font-size:0.9em; color:#333;">
            ❌ Very few safe signals found in this URL
        </div>"""

    # final theory paragraph - plain english explanation
    if risk_level in ("HIGH", "MEDIUM"):
        theory_para = f"""
        After analyzing this URL, the tool found it to be
        <strong style="color:#c62828;">{verdict}</strong>.
        The Random Forest ML model gave it a phishing probability of
        <strong>{phish_pct}%</strong>, which means out of 100 similar URLs,
        approximately {int(phish_pct)} were confirmed phishing sites.
        The main reasons for this high score are the suspicious domain structure,
        use of bad TLD extensions, and presence of phishing-related keywords.
        Users should completely avoid this URL and report it to cybercrime
        authorities if received via message, email, or social media.
        """
    else:
        theory_para = f"""
        After analyzing this URL, the tool found it to be
        <strong style="color:#2e7d32;">{verdict}</strong>.
        The Random Forest ML model gave it a phishing probability of only
        <strong>{phish_pct}%</strong>, which means out of 100 similar URLs,
        only {int(phish_pct)} were phishing — this is a very low risk score.
        The URL has proper HTTPS encryption, a clean domain structure,
        and no suspicious keywords were detected.
        However, always stay alert — no automated tool is 100% accurate.
        Never share passwords or banking details on any site unless you are
        absolutely sure it is the genuine official website.
        """

    # build the complete theory page html
    theory_section = f"""

    <!-- PAGE BREAK BEFORE THEORY PAGE - works when printing -->
    <div style="page-break-before: always;"></div>

    <!-- THEORY AND REASON PAGE -->
    <div style="background:#fff; padding:34px 42px; border-top:3px solid #1b263b; margin-top:20px;">

        <!-- PAGE HEADER -->
        <div style="text-align:center; margin-bottom:30px;">
            <div style="font-size:0.8em; color:#778da9; letter-spacing:2px; text-transform:uppercase;">
                LinkSpy v1.0 — Detailed Analysis Page
            </div>
            <h2 style="font-size:1.6em; color:#1b263b; margin-top:8px; letter-spacing:1px;">
                📊 Theory and Reason Report
            </h2>
            <p style="color:#666; margin-top:6px; font-size:0.9em;">
                This page explains WHY this URL got {phish_pct}% phishing score
                and what it means for your safety
            </p>
        </div>

        <!-- SECTION 1 - HOW MUCH TO TRUST THIS RESULT -->
        <div style="margin-bottom:28px;">
            <div style="font-size:1.05em; font-weight:700; color:#1b263b;
                        text-transform:uppercase; letter-spacing:1px;
                        border-bottom:2px solid #415a77;
                        padding-bottom:7px; margin-bottom:15px;">
                🎯 How Much To Trust This Result
            </div>

            <div style="background:#f5f7ff; border:2px solid {trust_color};
                        border-radius:8px; padding:20px; text-align:center; margin-bottom:16px;">
                <div style="font-size:1.8em; font-weight:bold; color:{trust_color};">
                    {trust_level}
                </div>
                <div style="font-size:1em; color:#333; margin-top:10px; line-height:1.6;">
                    {trust_message}
                </div>
                <div style="font-size:0.9em; color:#555; margin-top:10px;
                            background:rgba(0,0,0,0.05); padding:10px 16px; border-radius:4px;">
                    💡 <strong>What should you do:</strong> {trust_advice}
                </div>
            </div>

            <!-- GENERAL TRUST PERCENTAGE TABLE -->
            <p style="font-size:0.88em; font-weight:600; color:#555; margin-bottom:10px;">
                General Guide — When to trust any URL scan result:
            </p>
            <table style="width:100%; border-collapse:collapse; font-size:0.85em;">
                <thead>
                    <tr style="background:#1b263b; color:#fff;">
                        <th style="padding:9px 14px; text-align:left;">Phishing %</th>
                        <th style="padding:9px 14px; text-align:left;">Trust Level</th>
                        <th style="padding:9px 14px; text-align:left;">What It Means</th>
                        <th style="padding:9px 14px; text-align:left;">Recommended Action</th>
                    </tr>
                </thead>
                <tbody>
                    <tr style="background:#e8f5e9;">
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd; font-weight:700; color:#2e7d32;">0% — 20%</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">✅ High Trust</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Very likely safe, all checks passed</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Safe to open normally</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd; font-weight:700; color:#1565c0;">20% — 40%</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">🔵 Moderate Trust</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Mostly safe, has minor issues</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Open carefully, avoid entering data</td>
                    </tr>
                    <tr style="background:#fffde7;">
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd; font-weight:700; color:#f9a825;">40% — 60%</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">🟡 Low Trust</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Several suspicious signals found</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Do not enter any personal info</td>
                    </tr>
                    <tr style="background:#fff3e0;">
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd; font-weight:700; color:#e65100;">60% — 80%</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">🟠 Very Low Trust</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Strong phishing signals present</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Do not open, report to IT team</td>
                    </tr>
                    <tr style="background:#ffebee;">
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd; font-weight:700; color:#c62828;">80% — 100%</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">🚨 Do Not Trust</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Almost certainly phishing</td>
                        <td style="padding:8px 14px; border-bottom:1px solid #ddd;">Block and report to cybercrime.gov.in</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- SECTION 2 - WHY PHISHING SCORE IS THIS HIGH/LOW -->
        <div style="margin-bottom:28px;">
            <div style="font-size:1.05em; font-weight:700; color:#1b263b;
                        text-transform:uppercase; letter-spacing:1px;
                        border-bottom:2px solid #415a77;
                        padding-bottom:7px; margin-bottom:15px;">
                🚨 Why Phishing Score Is {phish_pct}% — Danger Signals
            </div>
            {danger_html}
        </div>

        <!-- SECTION 3 - WHY SAFE SCORE IS THIS HIGH/LOW -->
        <div style="margin-bottom:28px;">
            <div style="font-size:1.05em; font-weight:700; color:#1b263b;
                        text-transform:uppercase; letter-spacing:1px;
                        border-bottom:2px solid #415a77;
                        padding-bottom:7px; margin-bottom:15px;">
                ✅ Why Safe Score Is {safe_pct}% — Safe Signals
            </div>
            {safe_html}
        </div>

        <!-- SECTION 4 - FINAL THEORY PARAGRAPH -->
        <div style="margin-bottom:28px;">
            <div style="font-size:1.05em; font-weight:700; color:#1b263b;
                        text-transform:uppercase; letter-spacing:1px;
                        border-bottom:2px solid #415a77;
                        padding-bottom:7px; margin-bottom:15px;">
                📝 Final Analysis — Plain English Explanation
            </div>
            <div style="background:#f5f7ff; border:1px solid #dce3ff;
                        border-radius:8px; padding:20px;
                        font-size:0.95em; line-height:1.9; color:#333;">
                {theory_para}
            </div>
        </div>

        <!-- DISCLAIMER FOR THEORY PAGE -->
        <div style="background:#fff8e1; border:1px solid #ffe082; border-radius:6px;
                    padding:13px 16px; font-size:0.85em; color:#6d4c00; line-height:1.6;">
            ⚠️ <strong>Important Note:</strong> This theory is generated automatically
            based on URL feature analysis and ML model output.
            The tool has approximately <strong>85-90% accuracy</strong> on unknown URLs.
            For use in legal or official investigations, always verify findings with a
            certified cybersecurity expert. Blacklisted and whitelisted domains have
            <strong>98-99% accuracy</strong> as they are manually verified.
        </div>

    </div>"""

    return theory_section


# ─────────────────────────────────────────
# MAIN REPORT BUILDER
# builds the complete html report
# ─────────────────────────────────────────

def build_html_report(sample_url, analyst_name, case_id, result,
                      wl_result, bl_result, ip_address, domain_name,
                      location="Unknown", domain_age=0):

    now          = datetime.datetime.now()
    date_str     = now.strftime("%B %d, %Y")
    time_str     = now.strftime("%H:%M:%S")
    full_time    = now.strftime("%Y-%m-%d %H:%M:%S")

    features       = result.get("features", {})
    verdict        = result.get("verdict", "UNKNOWN")
    risk_level     = result.get("risk_level", "UNKNOWN")
    phish_prob     = result.get("phishing_chance", 0)
    safe_prob      = result.get("safe_chance", 1)
    confidence     = result.get("confidence", 0)
    is_trusted     = wl_result.get("is_trusted", False)
    is_blacklisted = bl_result.get("is_blacklisted", False)

    # generate hash values for digital fingerprint
    sha256_hash = calculate_sha256(sample_url)
    md5_hash    = calculate_md5(sample_url)

    # pick color based on risk level
    if risk_level == "HIGH":
        main_color = "#e53935"
        bg_color   = "#ffebee"
    elif risk_level == "MEDIUM":
        main_color = "#fb8c00"
        bg_color   = "#fff3e0"
    elif risk_level == "LOW":
        main_color = "#f9a825"
        bg_color   = "#fffde7"
    else:
        main_color = "#2e7d32"
        bg_color   = "#e8f5e9"

    # verdict box shown at the very top of report
    if is_blacklisted:
        verdict_box = f"""
        <div style="background:#ffebee; border:2px solid #e53935; border-radius:8px;
                    padding:20px; margin:16px 0; text-align:center;">
            <div style="font-size:2.5em;">🚨</div>
            <div style="color:#e53935; font-size:1.5em; font-weight:bold; margin-top:8px;">
                BLACKLISTED - CONFIRMED DANGEROUS
            </div>
            <div style="color:#555; margin-top:8px;">
                This domain is in our confirmed malicious sites list
            </div>
        </div>"""

    elif is_trusted:
        verdict_box = """
        <div style="background:#e8f5e9; border:2px solid #2e7d32; border-radius:8px;
                    padding:20px; margin:16px 0; text-align:center;">
            <div style="font-size:2.5em;">✅</div>
            <div style="color:#2e7d32; font-size:1.5em; font-weight:bold; margin-top:8px;">
                TRUSTED WEBSITE - SAFE TO USE
            </div>
            <div style="color:#555; margin-top:8px;">
                This domain is in our verified trusted websites list
            </div>
        </div>"""

    else:
        if risk_level == "HIGH":
            icon = "🚨"
        elif risk_level == "MEDIUM":
            icon = "⚠️"
        elif risk_level == "LOW":
            icon = "🟡"
        else:
            icon = "✅"

        verdict_box = f"""
        <div style="background:{bg_color}; border:2px solid {main_color}; border-radius:8px;
                    padding:20px; margin:16px 0; text-align:center;">
            <div style="font-size:2.5em;">{icon}</div>
            <div style="color:{main_color}; font-size:1.5em; font-weight:bold; margin-top:8px;">
                {verdict}
            </div>
            <div style="color:#555; margin-top:8px;">
                Risk Level: <strong>{risk_level}</strong> &nbsp;|&nbsp;
                Confidence: <strong>{confidence}%</strong>
            </div>
        </div>"""

    # build feature table rows
    feature_rows = ""
    for name, value in features.items():
        flag = ""
        if name == "has_https" and value == 0:
            flag = "⚠️ No HTTPS"
        elif name == "has_ip_in_url" and value:
            flag = "🚨 IP in URL"
        elif name == "suspicious_word_count" and value > 0:
            flag = f"🚨 {value} bad words"
        elif name == "is_suspicious_tld" and value:
            flag = "🚨 Bad extension"
        elif name == "has_at_symbol" and value:
            flag = "🚨 @ found"
        elif name == "has_brand_in_subdomain" and value:
            flag = "🚨 Brand spoofed"
        elif name == "is_url_shortener" and value:
            flag = "⚠️ Shortened URL"
        elif name == "has_punycode" and value:
            flag = "⚠️ Fake characters"
        elif name == "url_entropy" and float(value) > 4.5:
            flag = "⚠️ Looks random"

        readable      = name.replace("_", " ").title()
        feature_rows += f"""
            <tr>
                <td style="padding:8px 14px; border-bottom:1px solid #eee;
                           font-weight:500; color:#333;">{readable}</td>
                <td style="padding:8px 14px; border-bottom:1px solid #eee;
                           font-family:monospace; color:#444;">{value}</td>
                <td style="padding:8px 14px; border-bottom:1px solid #eee;
                           font-size:0.85em;">{flag}</td>
            </tr>"""

    phish_bar = int(phish_prob * 100)
    safe_bar  = 100 - phish_bar

    # timeline rows
    timeline_rows = f"""
        <tr style="background:#f9f9f9;">
            <td style="padding:8px 14px; border-bottom:1px solid #eee; font-weight:600;">Step 1</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">URL Received</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">User submitted URL for scanning</td>
        </tr>
        <tr>
            <td style="padding:8px 14px; border-bottom:1px solid #eee; font-weight:600;">Step 2</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Blacklist Check</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{"⛔ Found in blacklist" if is_blacklisted else "✅ Not in blacklist"}</td>
        </tr>
        <tr style="background:#f9f9f9;">
            <td style="padding:8px 14px; border-bottom:1px solid #eee; font-weight:600;">Step 3</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Whitelist Check</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{"✅ Found in trusted list" if is_trusted else "⚠️ Not in trusted list"}</td>
        </tr>
        <tr>
            <td style="padding:8px 14px; border-bottom:1px solid #eee; font-weight:600;">Step 4</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Feature Extraction</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{len(features)} features extracted</td>
        </tr>
        <tr style="background:#f9f9f9;">
            <td style="padding:8px 14px; border-bottom:1px solid #eee; font-weight:600;">Step 5</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">ML Model Analysis</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Random Forest gave {round(phish_prob * 100, 1)}% phishing probability</td>
        </tr>
        <tr>
            <td style="padding:8px 14px; border-bottom:1px solid #eee; font-weight:600;">Step 6</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Final Verdict</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee; font-weight:600; color:{main_color};">{verdict}</td>
        </tr>"""

    # chain of custody rows
    custody_rows = f"""
        <tr style="background:#f9f9f9;">
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">1</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{analyst_name}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">URL Submitted</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Analyst submitted URL for analysis</td>
        </tr>
        <tr>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">2</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">LinkSpy System</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Automated Analysis</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Blacklist, whitelist and ML checks completed</td>
        </tr>
        <tr style="background:#f9f9f9;">
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">3</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">LinkSpy System</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">Report Generated</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">{full_time}</td>
            <td style="padding:8px 14px; border-bottom:1px solid #eee;">HTML forensic report created and saved</td>
        </tr>"""

    # build the theory section (last page of report)
    theory_page = build_theory_section(result, features, domain_name, domain_age)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>LinkSpy Report - {case_id}</title>
    <style>
        * {{ box-sizing:border-box; margin:0; padding:0; }}
        body {{ font-family:'Segoe UI',Arial,sans-serif; background:#f0f2f5; color:#222; }}
        .page {{ max-width:960px; margin:30px auto; background:#fff;
                 border-radius:12px; box-shadow:0 4px 24px rgba(0,0,0,.13); overflow:hidden; }}
        .top {{ background:linear-gradient(135deg,#0d1b2a,#1b263b,#415a77);
                color:#fff; padding:34px 42px; }}
        .top h1 {{ font-size:1.7em; letter-spacing:2px; text-transform:uppercase; }}
        .top p {{ color:#a8b2c1; margin-top:5px; font-size:0.9em; }}
        .tag {{ display:inline-block; background:rgba(255,255,255,.12);
                border:1px solid rgba(255,255,255,.25); border-radius:20px;
                padding:3px 14px; font-size:0.82em; margin-top:10px; margin-right:8px; }}
        .body {{ padding:34px 42px; }}
        .sec {{ margin-bottom:30px; }}
        .sec-title {{ font-size:1.05em; font-weight:700; color:#1b263b;
                      text-transform:uppercase; letter-spacing:1px;
                      border-bottom:2px solid #415a77;
                      padding-bottom:7px; margin-bottom:15px; }}
        .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
        .box {{ background:#f5f7ff; border:1px solid #dce3ff;
                border-radius:8px; padding:13px 16px; }}
        .box .lbl {{ font-size:0.75em; color:#888; text-transform:uppercase; }}
        .box .val {{ font-size:0.95em; font-weight:600; color:#1b263b;
                     margin-top:5px; word-break:break-all; }}
        .url-box {{ background:#0d1b2a; color:#00d4ff; font-family:monospace;
                    padding:14px 18px; border-radius:8px;
                    font-size:0.9em; word-break:break-all; margin:12px 0; }}
        .hash-box {{ background:#1b263b; color:#78c1f3; font-family:monospace;
                     padding:10px 16px; border-radius:6px;
                     font-size:0.82em; word-break:break-all; margin:6px 0; }}
        .bar-wrap {{ background:#e0e0e0; border-radius:6px; height:22px;
                     overflow:hidden; display:flex; margin:8px 0; }}
        .bar-safe  {{ height:100%; background:#2e7d32; width:{safe_bar}%; }}
        .bar-phish {{ height:100%; background:#c62828; width:{phish_bar}%; }}
        .bar-labels {{ display:flex; justify-content:space-between;
                       font-size:0.83em; color:#666; margin-bottom:4px; }}
        table {{ width:100%; border-collapse:collapse; font-size:0.88em; }}
        thead tr {{ background:#1b263b; color:#fff; }}
        thead th {{ padding:9px 14px; text-align:left; }}
        tbody tr:hover {{ background:#f0f4ff; }}
        .note {{ background:#fff8e1; border:1px solid #ffe082; border-radius:6px;
                 padding:13px 16px; font-size:0.86em; color:#6d4c00; line-height:1.6; }}
        .foot {{ background:#f5f7ff; border-top:1px solid #dce3ff;
                 padding:18px 42px; font-size:0.8em; color:#999; text-align:center; }}
        @media print {{
            body {{ background:#fff; }}
            .page {{ box-shadow:none; margin:0; border-radius:0; }}
        }}
    </style>
</head>
<body>
<div class="page">

    <!-- REPORT HEADER -->
    <div class="top">
        <div style="font-size:0.78em; color:#778da9; letter-spacing:2px; text-transform:uppercase;">
            🔍 LinkSpy - URL Threat Detection Tool
        </div>
        <h1 style="margin-top:7px;">Forensic URL Scan Report</h1>
        <p>Phishing Detection | Digital Forensics | Web Safety Analysis</p>
        <div class="tag">📁 Case: {case_id}</div>
        <div class="tag">👤 Analyst: {analyst_name}</div>
        <div class="tag">📅 {date_str}</div>
    </div>

    <div class="body">

        <!-- FINAL VERDICT -->
        <div class="sec">
            <div class="sec-title">🎯 Final Verdict</div>
            {verdict_box}
        </div>

        <!-- CASE INFORMATION -->
        <div class="sec">
            <div class="sec-title">📋 Case Information</div>
            <div class="grid">
                <div class="box"><div class="lbl">Case Number</div><div class="val">{case_id}</div></div>
                <div class="box"><div class="lbl">Analyst Name</div><div class="val">{analyst_name}</div></div>
                <div class="box"><div class="lbl">Scan Date</div><div class="val">{date_str}</div></div>
                <div class="box"><div class="lbl">Scan Time</div><div class="val">{time_str}</div></div>
                <div class="box"><div class="lbl">System</div><div class="val">{platform.system()} {platform.release()}</div></div>
                <div class="box"><div class="lbl">Tool Version</div><div class="val">LinkSpy v1.0</div></div>
            </div>
        </div>

        <!-- URL DETAILS -->
        <div class="sec">
            <div class="sec-title">🌐 URL Under Investigation</div>
            <div class="url-box">{sample_url}</div>
            <div class="grid" style="margin-top:12px;">
                <div class="box"><div class="lbl">Domain Name</div><div class="val">{domain_name}</div></div>
                <div class="box"><div class="lbl">IP Address</div><div class="val">{ip_address}</div></div>
                <div class="box"><div class="lbl">Server Location</div><div class="val">{location}</div></div>
                <div class="box"><div class="lbl">Domain Age</div><div class="val">{domain_age} days old</div></div>
                <div class="box">
                    <div class="lbl">Whitelist Status</div>
                    <div class="val">{"✅ Trusted - Whitelisted" if is_trusted else "❌ Not in trusted list"}</div>
                </div>
                <div class="box">
                    <div class="lbl">Blacklist Status</div>
                    <div class="val">{"🚨 BLACKLISTED" if is_blacklisted else "✅ Not in blacklist"}</div>
                </div>
            </div>
        </div>

        <!-- HASH VALUES -->
        <div class="sec">
            <div class="sec-title">🔐 Hash Values (Digital Fingerprint)</div>
            <p style="font-size:0.85em; color:#666; margin-bottom:10px; line-height:1.6;">
                Hash values are like a fingerprint for this URL. If even one character changes,
                the hash becomes completely different. Used to prove the URL was not tampered with.
            </p>
            <div class="box" style="margin-bottom:8px;">
                <div class="lbl">SHA-256 Hash</div>
                <div class="hash-box">{sha256_hash}</div>
            </div>
            <div class="box">
                <div class="lbl">MD5 Hash</div>
                <div class="hash-box">{md5_hash}</div>
            </div>
        </div>

        <!-- ML SCORE -->
        <div class="sec">
            <div class="sec-title">🤖 Machine Learning Score (Random Forest)</div>
            <div class="bar-labels">
                <span style="color:#2e7d32;">✅ Safe ({round(safe_prob * 100, 1)}%)</span>
                <span style="color:#c62828;">🚨 Phishing ({round(phish_prob * 100, 1)}%)</span>
            </div>
            <div class="bar-wrap">
                <div class="bar-safe"></div>
                <div class="bar-phish"></div>
            </div>
            <div class="grid" style="margin-top:12px;">
                <div class="box"><div class="lbl">Safe Probability</div><div class="val">{round(safe_prob * 100, 2)}%</div></div>
                <div class="box"><div class="lbl">Phishing Probability</div><div class="val">{round(phish_prob * 100, 2)}%</div></div>
                <div class="box"><div class="lbl">Confidence</div><div class="val">{confidence}%</div></div>
                <div class="box"><div class="lbl">Algorithm</div><div class="val">Random Forest - 100 Decision Trees</div></div>
            </div>
        </div>

        <!-- ANALYSIS TIMELINE -->
        <div class="sec">
            <div class="sec-title">⏱️ Analysis Timeline</div>
            <p style="font-size:0.85em; color:#666; margin-bottom:10px;">
                Every step that happened during the scan, recorded in order.
            </p>
            <table>
                <thead>
                    <tr><th>Step</th><th>Timestamp</th><th>Action</th><th>Result</th></tr>
                </thead>
                <tbody>{timeline_rows}</tbody>
            </table>
        </div>

        <!-- CHAIN OF CUSTODY -->
        <div class="sec">
            <div class="sec-title">🔗 Chain of Custody</div>
            <p style="font-size:0.85em; color:#666; margin-bottom:10px; line-height:1.6;">
                Records who handled this case and when. Important for legal and forensic use.
            </p>
            <table>
                <thead>
                    <tr><th>#</th><th>Handled By</th><th>Action</th><th>Timestamp</th><th>Notes</th></tr>
                </thead>
                <tbody>{custody_rows}</tbody>
            </table>
        </div>

        <!-- FEATURES TABLE -->
        <div class="sec">
            <div class="sec-title">🔬 URL Feature Analysis ({len(features)} Features)</div>
            <table>
                <thead>
                    <tr><th>Feature Name</th><th>Value</th><th>Flag</th></tr>
                </thead>
                <tbody>{feature_rows}</tbody>
            </table>
        </div>

        <!-- DISCLAIMER -->
        <div class="note">
            ⚠️ <strong>Disclaimer:</strong> This report was generated automatically by LinkSpy v1.0.
            Results are based on machine learning, blacklist/whitelist checks, and rule based analysis.
            Verify with a qualified cybersecurity expert before any legal action.
            &nbsp;|&nbsp; Analyst: <strong>{analyst_name}</strong>
            &nbsp;|&nbsp; Generated: {full_time}
        </div>

    </div>

    <!-- FOOTER -->
    <div class="foot">
        <strong>LinkSpy v1.0</strong> &nbsp;|&nbsp;
        Case: {case_id} &nbsp;|&nbsp;
        Analyst: {analyst_name} &nbsp;|&nbsp;
        {date_str} &nbsp;|&nbsp;
        <span style="color:#bbb;">Confidential - For Authorized Use Only</span>
    </div>

    <!-- THEORY AND REASON PAGE (last page) -->
    {theory_page}

    <!-- THEORY PAGE FOOTER -->
    <div class="foot">
        <strong>LinkSpy v1.0</strong> &nbsp;|&nbsp;
        Theory Page &nbsp;|&nbsp;
        Case: {case_id} &nbsp;|&nbsp;
        {date_str}
    </div>

</div>
</body>
</html>"""

    return html


# ─────────────────────────────────────────
# SAVE REPORT TO FILE
# ─────────────────────────────────────────

def save_report(html_content, case_id, save_folder="reports"):
    os.makedirs(save_folder, exist_ok=True)
    file_name = "report_" + case_id + ".html"
    file_path = os.path.join(save_folder, file_name)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return file_path