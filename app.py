import os
import sys
import streamlit as st

# same path setup
sys.path.insert(0, os.path.dirname(__file__))

# SAME imports (unchanged)
from features import extract_features
from features import extract_domain_from_url
from features import get_ip_address
from features import is_trusted_domain
from features import is_domain_blacklisted
from features import get_location_from_ip
from features import get_domain_age
from ml_model import load_saved_model
from ml_model import run_prediction
from ml_model import make_case_id
from report_generator import build_html_report
from report_generator import save_report

# -------------------- STREAMLIT SETUP --------------------
st.set_page_config(page_title="LinkSpy", layout="wide")

st.title("🔍 LinkSpy - URL Threat Detection Tool")

# SAME model loading (just cached)
@st.cache_resource
def load_model():
    print("Loading ML model...")
    model, columns = load_saved_model()
    return model, columns

my_model, column_names = load_model()

# SAME reports folder
REPORTS_FOLDER = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# -------------------- INPUT UI --------------------
url = st.text_input("Enter URL to scan")
analyst_name = st.text_input("Examiner Name", value="Unknown Analyst")
case_id_input = st.text_input("Case Number (optional)")

# -------------------- ANALYZE BUTTON --------------------
if st.button("🚀 Analyze URL"):

    if not url:
        st.error("Please enter a URL to scan")
        st.stop()

    # SAME case id logic
    case_id = case_id_input if case_id_input else make_case_id()

    # SAME URL fixing logic
    if not url.startswith("http://") and not url.startswith("https://"):
        final_url = "http://" + url
    else:
        final_url = url

    st.info("Analyzing... please wait ⏳")

    # -------------------- SAME PROCESSING --------------------
    domain_name = extract_domain_from_url(final_url)
    ip_address = get_ip_address(domain_name)
    location = get_location_from_ip(ip_address)
    domain_age = get_domain_age(domain_name)

    bl_result = is_domain_blacklisted(final_url)
    wl_result = is_trusted_domain(final_url)

    ml_result = run_prediction(final_url, my_model, column_names)

    # SAME override logic
    if bl_result["is_blacklisted"]:
        ml_result["verdict"] = "BLACKLISTED - CONFIRMED DANGEROUS"
        ml_result["risk_level"] = "HIGH"
        ml_result["phishing_chance"] = 0.99
        ml_result["safe_chance"] = 0.01
        ml_result["confidence"] = 99.0

    elif wl_result["is_trusted"]:
        ml_result["verdict"] = "SAFE - TRUSTED WEBSITE"
        ml_result["risk_level"] = "MINIMAL"
        ml_result["phishing_chance"] = 0.02
        ml_result["safe_chance"] = 0.98
        ml_result["confidence"] = 98.0

    # -------------------- DISPLAY --------------------
    st.subheader("📊 Scan Results")

    col1, col2 = st.columns(2)

    with col1:
        st.write("**URL:**", final_url)
        st.write("**Domain:**", domain_name)
        st.write("**IP Address:**", ip_address)
        st.write("**Location:**", location)

    with col2:
        st.write("**Domain Age (days):**", domain_age)
        st.write("**Case ID:**", case_id)
        st.write("**Examiner:**", analyst_name)

    st.divider()

    st.subheader("🧠 ML Prediction")
    st.success(ml_result["verdict"])
    st.write("Risk Level:", ml_result["risk_level"])
    st.write("Confidence:", ml_result["confidence"])

    st.write("Phishing Probability:", ml_result["phishing_chance"])
    st.write("Safe Probability:", ml_result["safe_chance"])

    # -------------------- REPORT GENERATION (SAME) --------------------
    report_html = build_html_report(
        sample_url=final_url,
        analyst_name=analyst_name,
        case_id=case_id,
        result=ml_result,
        wl_result=wl_result,
        bl_result=bl_result,
        ip_address=ip_address,
        domain_name=domain_name,
        location=location,
        domain_age=domain_age,
    )

    saved_path = save_report(report_html, case_id, REPORTS_FOLDER)
    report_file = os.path.basename(saved_path)

    st.success("✅ Report Generated Successfully!")

    # download button
    with open(saved_path, "r", encoding="utf-8") as f:
        st.download_button(
            label="📥 Download Report",
            data=f.read(),
            file_name=report_file,
            mime="text/html"
        )

# -------------------- RETRAIN BUTTON --------------------
st.divider()

if st.button("🔄 Retrain Model"):
    from ml_model import train_fresh_model
    my_model, column_names = train_fresh_model()
    st.success("Model retrained successfully!")
