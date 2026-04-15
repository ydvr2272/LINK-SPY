import re
import math
import socket
import urllib.parse
import os
import requests
import whois
from datetime import datetime

#-----------WHITELIST----------#
WHITELIST = {
    # (same as your code)
}

#------------SUSPICIOUS WORD-----------#
SUSPICIOUS_WORDS = [
    # login related
    "login", "signin", "sign-in", "log-in", "username", "password", "passwd", "sign-up",
     
    # account related
    "account", "private account", "verify", "verification", "confirm", "confirmation", "validate", 
    
    # banking related
    "banking", "netbanking", "bank", "transaction", "transfer", "payment", "kyc",    
    
    # urgent words that makes user panic
    "urgent", "alert", "warning", "suspend", "suspended", "blocked", "locked", "limited", "unusual", "activity",
    
    # free/prize related words used to exiting the user
    "free", "winner", "prize", "lucky", "selected", "claim", "bonus", "reward", "gift", "offer", "congratulations",
    
    # kyc related to put user in rush
    "kyc", "aadhar", "pan", "update", "expire", "expired", "renewal",
    
    # money related words that attracts the users 
    "loan", "credit", "cashback", "refund", "recharge", "earn",
    
    # crypto related manupiulative word 
    "bitcoin", "crypto", "wallet",
    
    # brand names used in phishing attack urls 
    "paypal", "amazon", "apple", "microsoft", "google", "facebook", "sbi", "hdfc", "icici", "paytm",
]

PHISHING_TOP_LEVEL_DOMAIN= [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online",
    ".site", ".website", ".tech", ".info", ".biz", ".click", ".download",
]

URL_SHORTENERS= [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "shorte.st", "adf.ly", "tiny.cc", "rebrand.ly", "cutt.ly",
    "shorturl.at", "t.ly", "cutt.us",
]

def read_blacklist():
    try:
        blacklist_path = os.path.join(os.path.dirname(__file__), "blacklist.txt")
        with open(blacklist_path, "r") as file:
            blacklist_urls = set(line.strip().lower() for line in file if line.strip())
            print(f"Blacklist loaded :{len(blacklist_urls)} total URLs found")
            return blacklist_urls
    except FileNotFoundError:
        print("blacklist.txt not found, blacklist is empty")
        return set()

BLACKLISTED = read_blacklist()

def extract_domain_from_url(sample_url):
    try:
        if sample_url=="":
            return ""
        
        if not sample_url.startswith(("http://", "https://")):
            sample_url = "https://" + sample_url
        
        parsed_url = urllib.parse.urlparse(sample_url)
        domain_name = parsed_url.netloc
         
        domain_name = domain_name.lower().replace("www.", "")
        
        return domain_name
    
    except:
        return sample_url.lower()


def get_ip_address(domain_name):
    try:
        # FIX: gethostbyname_ex returns tuple → extract IP
        ip_address = socket.gethostbyname_ex(domain_name)[2][0]
        return ip_address
    except socket.gaierror:
        return "N/A"
    

def is_trusted_domain(sample_url):
    try:
        main_domain = extract_domain_from_url(sample_url)
        
        if main_domain in WHITELIST:
            return {"is_trusted": True, "checked_domain": main_domain}
        
        domain_parts = main_domain.split(".")
        
        for i in range(len(domain_parts)):
            parent = ".".join(domain_parts[i:])
            
            if parent in WHITELIST:
                return {"is_trusted": True, "checked_domain": main_domain}
        
        return {"is_trusted": False, "checked_domain": main_domain}
    except Exception:
        return {"is_trusted": False, "checked_domain": sample_url}
    

def is_domain_blacklisted(sample_url):
    try:
        domain_name = extract_domain_from_url(sample_url)
        
        if domain_name in BLACKLISTED:
            return {"is_blacklisted": True, "checked_domain": domain_name}
        
        domain_parts = domain_name.split(".")
        
        for i in range(len(domain_parts)):
            parent_domain = ".".join(domain_parts[i:])
            
            if parent_domain in BLACKLISTED:
                return {"is_blacklisted": True, "checked_domain": domain_name}
        
        return {"is_blacklisted": False, "checked_domain": domain_name}
    
    except Exception:
        return {"is_blacklisted": False, "checked_domain": sample_url}


def calculate_entropy(input_text):
    try:
        if input_text == "":
            return 0.0
        
        frequency_count = {}
        for ch in input_text:
            if ch in frequency_count:
                frequency_count[ch] += 1
            else:
                frequency_count[ch] = 1
        
        length = len(input_text)
        result = 0
        
        for value in frequency_count.values():
            p = value / length
            result = result - (p * math.log2(p))
        
        return round(result, 4)
    
    except:
        return 0.0
    

def get_location_from_ip(ip_address):
    try:
        if ip_address == "":
            return "Unknown"
        
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url)
        
        data = response.json()
        
        if data["status"] == "success":
            city = data.get("city", "")
            region = data.get("regionName", "")
            country = data.get("country", "")
            
            location = city + ", " + region + ", " + country
            return location
        else:
            return "Location not found"
    
    except Exception:
        return "Error"


def get_domain_age(domain_name):
    try:
        if domain_name == "":
            return 0
        
        domain_info = whois.whois(domain_name)
        
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date is None:
            return 0
        
        current_date = datetime.now()
        
        age = (current_date - creation_date).days
        
        return age
    
    except Exception:
        return 0
    
if __name__ == "__main__":
    test_url = "https://google.com"
    
    print("Domain:", extract_domain_from_url(test_url))
    print("Trusted:", is_trusted_domain(test_url))
    print("Blacklisted:", is_domain_blacklisted(test_url))
    
    domain = extract_domain_from_url(test_url)
    
    ip = get_ip_address(domain)
    print("IP Address:", ip)
    
    print("Location:", get_location_from_ip(ip))
    print("Entropy:", calculate_entropy(test_url))
    print("Domain Age:", get_domain_age(domain))   

def extract_features(sample_url):
    try:
        # add https if missing
        if not sample_url.startswith(("http://", "https://")):
            sample_url = "https://" + sample_url

        parsed     = urllib.parse.urlparse(sample_url)
        domain     = extract_domain_from_url(sample_url)
        path       = parsed.path
        query      = parsed.query
        full_url   = sample_url.lower()
        scheme     = parsed.scheme.lower()

    except:
        domain = path = query = full_url = scheme = ""

    # get subdomains
    parts      = domain.split(".")
    subdomains = parts[:-2] if len(parts) > 2 else []

    # check if ip address is used instead of domain
    ip_pattern = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    has_ip     = 1 if ip_pattern.search(domain) else 0

    # check if domain ends with a bad tld like .tk .xyz
    is_bad_tld = 0
    for tld in PHISHING_TOP_LEVEL_DOMAIN:
        if domain.endswith(tld):
            is_bad_tld = 1
            break

    # check if url is a shortener like bit.ly
    is_short = 1 if any(s in domain for s in URL_SHORTENERS) else 0

    # count how many suspicious words are in the url
    word_count = sum(1 for w in SUSPICIOUS_WORDS if w in full_url)

    # check if a brand name is used in subdomain to trick users
    brand_names = [
        "paypal", "google", "apple", "microsoft", "amazon",
        "facebook", "sbi", "hdfc", "icici", "paytm", "phonepe"
    ]
    has_brand = 1 if any(b in ".".join(subdomains) for b in brand_names) else 0

    # check if a non standard port is used
    port     = parsed.port or 0
    has_port = 1 if port and port not in (80, 443) else 0

    return {
        # length based features
        "url_length":              len(sample_url),
        "domain_length":           len(domain),
        "path_length":             len(path),
        # count based features
        "num_dots":                sample_url.count("."),
        "num_hyphens":             sample_url.count("-"),
        "num_underscores":         sample_url.count("_"),
        "num_slashes":             sample_url.count("/"),
        "num_at_symbols":          sample_url.count("@"),
        "num_question_marks":      sample_url.count("?"),
        "num_equals":              sample_url.count("="),
        "num_ampersands":          sample_url.count("&"),
        "num_percent":             sample_url.count("%"),
        # digit features
        "num_digits_url":          sum(c.isdigit() for c in sample_url),
        "num_digits_domain":       sum(c.isdigit() for c in domain),
        "digit_ratio_url":         round(sum(c.isdigit() for c in sample_url) / max(len(sample_url), 1), 4),
        "digit_ratio_domain":      round(sum(c.isdigit() for c in domain) / max(len(domain), 1), 4),
        # entropy features
        "url_entropy":             calculate_entropy(sample_url),
        "domain_entropy":          calculate_entropy(domain),
        "path_entropy":            calculate_entropy(path),
        # keyword features
        "suspicious_word_count":   word_count,
        # structural features
        "has_https":               1 if scheme == "https" else 0,
        "has_ip_in_url":           has_ip,
        "has_at_symbol":           1 if "@" in sample_url else 0,
        "has_double_slash":        1 if "//" in path else 0,
        "has_hex_encoding":        1 if re.search(r"%[0-9a-fA-F]{2}", sample_url) else 0,
        "subdomain_count":         len(subdomains),
        "has_port":                has_port,
        "port_number":             port,
        "has_fragment":            1 if parsed.fragment else 0,
        "query_param_count":       len(urllib.parse.parse_qs(query)),
        "path_depth":              len([p for p in path.split("/") if p]),
        "is_suspicious_tld":       is_bad_tld,
        "is_url_shortener":        is_short,
        "has_punycode":            1 if "xn--" in domain else 0,
        "has_redirect_param":      1 if any(p in query.lower() for p in ["redirect", "url=", "next=", "goto="]) else 0,
        "is_long_url":             1 if len(sample_url) > 75 else 0,
        "is_very_long_url":        1 if len(sample_url) > 100 else 0,
        "has_multiple_subdomains": 1 if len(subdomains) > 2 else 0,
        "has_brand_in_subdomain":  has_brand,
    }