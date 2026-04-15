#  URLGuard Forensic — URL Threat Detection Tool

> Professional URL analysis with 3-layer detection, Random Forest ML, and forensic report generation.

---

##  Project Structure

```
url_detector/
├── app.py                  # Flask web application (main entry)
├── features.py             # Lexical & structural feature extraction
├── ml_model.py             # Random Forest classifier (pure Python)
├── report_generator.py     # Forensic HTML report generator
├── run.py                  # One-click setup & launcher
├── requirements.txt        # Python dependencies (only Flask!)
├── templates/
│   └── index.html          # Web UI
├── models/
│   └── rf_model.pkl        # Saved Random Forest model (auto-generated)
└── reports/                # Generated forensic reports (HTML)
```

---

##  Quick Start

### Option 1: One-click (recommended)
```bash
python run.py
```


Then open: **http://localhost:5000**

---

##  How It Works — 3 Layers

### Layer 1: Whitelist Check
- Checks 50+ trusted domains (Google, Microsoft, GitHub, etc.)
- Subdomain-aware (e.g., `mail.google.com` → trusted)
- Instant SAFE verdict if whitelisted

### Layer 2: Feature Extraction (19 Lexical + 19 Structural = 38 Features)

**Lexical Features:**
- URL length, domain length, path length
- Character counts: dots, hyphens, slashes, @, ?, =, &, %
- Digit ratios (URL & domain)
- Shannon entropy (URL, domain, path)
- Suspicious keyword count (login, verify, secure, etc.)

**Structural Features:**
- HTTPS presence
- IP address in URL
- @ symbol in URL
- Double slash in path
- Hex/percent encoding
- Subdomain count
- Port number presence
- Fragment presence
- Query parameter count
- Path depth
- Suspicious TLD (.tk, .xyz, .ml, etc.)
- URL shortener detection
- Punycode/IDN detection
- Redirect parameter detection
- URL length flags
- Multiple subdomains flag
- Brand name in subdomain (spoofing detection)

### Layer 3: Random Forest ML
- 100 decision trees
- Max depth: 8
- Features used: sqrt(38) ≈ 6 per split
- Bootstrap sampling for each tree
- Probability averaging for final score
- Pure Python — no sklearn required!

---

##  Verdict Levels

| Risk Level | Probability | Verdict |
|------------|-------------|---------|
| MINIMAL | < 30% | ✅ SAFE |
| LOW | 30–50% | 🟡 LIKELY SAFE |
| MEDIUM | 50–75% |  ⚠️ SUSPICIOUS |
| HIGH | ≥ 75% | 🚨 PHISHING / MALICIOUS |

---

##  Forensic Report

Each analysis generates a professional HTML forensic report containing:

- **Case Number** (auto-generated: CASE-YYYYMMDD-XXXX)
- **Examiner Name**
- **Date & Time** of examination
- **Analysis System** (OS info)
- **Tool Version**
- **Full URL** under examination
- **Domain & IP Address**
- **Whitelist Status**
- **ML Probability Scores** (visual bar chart)
- **All 38 extracted features** with flags
- **Threat Indicators Summary** table
- **Legal Disclaimer**

Reports are saved as HTML files in the `reports/` folder and can be:
- Viewed in browser (full formatted report)
- Downloaded for case files
- Printed as PDF from browser (Ctrl+P)

---

##  API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web UI |
| POST | `/analyze` | Analyze a URL |
| GET | `/view_report/<filename>` | View report in browser |
| GET | `/download_report/<filename>` | Download report |
| POST | `/retrain` | Retrain the model |

### POST /analyze — Request
```json
{
  "url": "https://suspicious-login.tk/verify?id=12345",
  "examiner_name": "Jane Smith",
  "case_number": "CASE-20240101-ABCD"
}
```

---

##  Cross-Platform Compatibility

| Platform | Status |
|----------|--------|
| Windows 10/11 | 💯 Full Support |
| macOS 12+ | 💯 Full Support |
| Linux (Ubuntu, Kali, etc.) | 💯 Full Support |

Requirements: Python 3.8+ and Flask only. No heavy ML libraries needed.

---

##  VS Code Setup

1. Open the `url_detector/` folder in VS Code
2. Open terminal: `Ctrl+\``
3. Run: `python run.py`
4. Open browser: `http://localhost:5000`

**Recommended VS Code Extensions:**
- Python (Microsoft)
- Pylance
- HTML CSS Support

---

##  Accuracy

The model trains on synthetically generated benign and phishing URL patterns designed to reflect real-world distributions:

- Benign: 20 trusted domains × multiple paths
- Phishing: 200 generated phishing-style URLs with known patterns

To improve accuracy with real data:
1. Collect labeled URL datasets (PhishTank, OpenPhish, Alexa Top 1M)
2. Place them in CSV format: `url,label` (0=safe, 1=phishing)
3. Modify `train_model()` in `ml_model.py` to load your dataset

---

##  Legal Notice

This tool is designed exclusively for:
- Digital forensics investigations
- Cybersecurity research and education
- Threat intelligence analysis
- Security awareness training

Do not use for unauthorized surveillance or illegal purposes.