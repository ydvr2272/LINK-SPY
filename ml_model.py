import os
import pickle
import random

# importing from my features file
# note: using exact same names as defined in features.py
from features import extract_features
from features import is_trusted_domain
from features import is_domain_blacklisted

# my trained model will be saved at this path
MODEL_FILE = os.path.join(os.path.dirname(__file__), "models", "linkspy_model.pkl")


# -----------------------------------------------
# DECISION TREE CLASS
# think of it like a flowchart that asks questions
# about the url and gives safe or phishing answer
# -----------------------------------------------

class MyDecisionTree:

    def __init__(self, max_depth=8, min_samples=4):
        # max_depth = how many levels deep the tree can go
        # min_samples = stop splitting if very few samples left
        self.max_depth   = max_depth
        self.min_samples = min_samples
        self.tree        = None

    def calculate_gini(self, labels):
        # gini tells how mixed a group is
        # 0 = all same label (pure) --- 0.5 = totally mixed
        total = len(labels)
        if total == 0:
            return 0

        phishing_count = labels.count(1)
        safe_count     = labels.count(0)
        phishing_ratio = phishing_count / total
        safe_ratio     = safe_count / total

        gini = 1 - (phishing_ratio ** 2 + safe_ratio ** 2)
        return gini

    def find_best_split(self, X, y, feature_list):
        # we try different split points on each feature
        # and pick the one that best separates safe from phishing
        best_gain      = -1
        best_feature   = None
        best_threshold = None
        parent_gini    = self.calculate_gini(y)
        total          = len(y)

        for feature in feature_list:
            all_values = sorted(set(row[feature] for row in X))

            for i in range(len(all_values) - 1):
                mid = (all_values[i] + all_values[i + 1]) / 2

                left_y  = [y[j] for j, row in enumerate(X) if row[feature] <= mid]
                right_y = [y[j] for j, row in enumerate(X) if row[feature] > mid]

                if not left_y or not right_y:
                    continue

                gain = parent_gini - (
                    len(left_y)  / total * self.calculate_gini(left_y) +
                    len(right_y) / total * self.calculate_gini(right_y)
                )

                if gain > best_gain:
                    best_gain      = gain
                    best_feature   = feature
                    best_threshold = mid

        return best_feature, best_threshold

    def build_tree(self, X, y, depth, features):
        # stop conditions
        if depth >= self.max_depth:
            return self.make_leaf(y)
        if len(y) < self.min_samples:
            return self.make_leaf(y)
        if len(set(y)) == 1:
            return self.make_leaf(y)

        best_feature, best_threshold = self.find_best_split(X, y, features)

        if best_feature is None:
            return self.make_leaf(y)

        left_idx  = [i for i, row in enumerate(X) if row[best_feature] <= best_threshold]
        right_idx = [i for i, row in enumerate(X) if row[best_feature] > best_threshold]

        left_X  = [X[i] for i in left_idx]
        left_y  = [y[i] for i in left_idx]
        right_X = [X[i] for i in right_idx]
        right_y = [y[i] for i in right_idx]

        return {
            "leaf":      False,
            "feature":   best_feature,
            "threshold": best_threshold,
            "left":      self.build_tree(left_X,  left_y,  depth + 1, features),
            "right":     self.build_tree(right_X, right_y, depth + 1, features),
        }

    def make_leaf(self, y):
        total          = len(y)
        phishing_count = y.count(1)
        probability    = phishing_count / total if total > 0 else 0
        return {
            "leaf":        True,
            "probability": probability,
        }

    def train(self, X, y, num_features=None):
        all_features = list(range(len(X[0])))
        if num_features is None:
            num_features = max(1, int(len(all_features) ** 0.5))
        picked    = random.sample(all_features, min(num_features, len(all_features)))
        self.tree = self.build_tree(X, y, depth=0, features=picked)

    def get_prob(self, node, row):
        if node["leaf"]:
            return node["probability"]
        if row[node["feature"]] <= node["threshold"]:
            return self.get_prob(node["left"], row)
        return self.get_prob(node["right"], row)

    def predict(self, X):
        return [self.get_prob(self.tree, row) for row in X]


# -----------------------------------------------
# RANDOM FOREST CLASS
# 100 trees vote together - majority wins
# this gives better accuracy than one tree alone
# -----------------------------------------------

class MyRandomForest:

    def __init__(self, total_trees=100, max_depth=8, min_samples=4):
        self.total_trees  = total_trees
        self.max_depth    = max_depth
        self.min_samples  = min_samples
        self.all_trees    = []
        self.column_names = None

    def train(self, X, y):
        num_features   = max(1, int(len(X[0]) ** 0.5))
        self.all_trees = []
        print(f"Training {self.total_trees} trees, please wait...")

        for i in range(self.total_trees):
            # bootstrap sampling = pick random rows with repetition allowed
            idx      = [random.randint(0, len(X) - 1) for _ in range(len(X))]
            X_sample = [X[j] for j in idx]
            y_sample = [y[j] for j in idx]

            one_tree = MyDecisionTree(
                max_depth   = self.max_depth,
                min_samples = self.min_samples
            )
            one_tree.train(X_sample, y_sample, num_features=num_features)
            self.all_trees.append(one_tree)

        print("All trees done!")

    def get_probability(self, X):
        # each tree gives a probability, we average all of them
        all_preds = [tree.predict(X) for tree in self.all_trees]
        result    = []
        for i in range(len(X)):
            avg = sum(all_preds[t][i] for t in range(len(self.all_trees))) / len(self.all_trees)
            result.append(avg)
        return result

    def predict(self, X):
        probs = self.get_probability(X)
        return [1 if p >= 0.5 else 0 for p in probs]


# -----------------------------------------------
# TRAINING DATA
# i made these safe and fake urls to train model
# -----------------------------------------------

def make_safe_urls():
    safe_sites = [
        "google.com", "youtube.com", "facebook.com", "github.com",
        "amazon.com", "wikipedia.org", "twitter.com", "linkedin.com",
        "microsoft.com", "apple.com", "reddit.com", "netflix.com",
        "dropbox.com", "zoom.us", "slack.com", "discord.com",
        "sbi.co.in", "hdfcbank.com", "icicibank.com", "flipkart.com",
        "irctc.co.in", "incometax.gov.in", "gov.in", "nic.in",
        "paytm.com", "phonepe.com", "zerodha.com", "naukri.com",
        "byjus.com", "zomato.com", "swiggy.com", "myntra.com",
        "timesofindia.com", "ndtv.com", "jio.com", "razorpay.com",
        "groww.in", "meesho.com", "uidai.gov.in", "digilocker.gov.in",
    ]
    paths    = ["/", "/about", "/login", "/help", "/home"]
    all_urls = []
    for site in safe_sites:
        for path in paths:
            all_urls.append("https://" + site + path)
    return all_urls


def make_phishing_urls():
    patterns = [
        "http://secure-{brand}-login.{tld}/verify?id={num}",
        "http://{brand}-update.{tld}/reset/password",
        "http://{ip}/phishing/login.php?go={brand}",
        "http://www.{brand}-alert.{tld}/account/suspended",
        "http://free-prize-{brand}.{tld}/claim/now",
        "http://{brand}.fake-site.{tld}/update?token={num}",
        "http://192.168.{num}.1/admin/login.php",
    ]
    brands = [
        "paypal", "google", "apple", "microsoft", "amazon",
        "facebook", "netflix", "sbi", "hdfc", "icici",
        "paytm", "phonepe", "irctc", "flipkart",
    ]
    tlds     = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "online", "site"]
    all_urls = []

    for _ in range(300):
        pattern = random.choice(patterns)
        brand   = random.choice(brands)
        tld     = random.choice(tlds)
        ip      = ".".join(str(random.randint(1, 254)) for _ in range(4))
        num     = str(random.randint(1000, 99999))

        url = pattern.replace("{brand}", brand)
        url = url.replace("{tld}", tld)
        url = url.replace("{ip}", ip)
        url = url.replace("{num}", num)
        all_urls.append(url)

    return all_urls


def train_fresh_model():
    print("Preparing training data...")
    safe_urls     = make_safe_urls()
    phishing_urls = make_phishing_urls()

    X            = []
    y            = []
    column_names = None

    for url in safe_urls:
        f = extract_features(url)
        if column_names is None:
            column_names = list(f.keys())
        X.append(list(f.values()))
        y.append(0)

    for url in phishing_urls:
        f = extract_features(url)
        X.append(list(f.values()))
        y.append(1)

    print(f"Total: {len(X)} samples | Safe: {y.count(0)} | Phishing: {y.count(1)}")

    forest             = MyRandomForest(total_trees=100, max_depth=8)
    forest.train(X, y)
    forest.column_names = column_names

    os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(forest, f)

    print("Model saved!")
    return forest, column_names


def load_saved_model():
    if os.path.exists(MODEL_FILE):
        print("Found saved model, loading...")
        with open(MODEL_FILE, "rb") as f:
            forest = pickle.load(f)
        # if old model class - retrain with new class
        if not isinstance(forest, MyRandomForest):
            print("Old model detected, retraining...")
            return train_fresh_model()
        print("Model ready!")
        return forest, forest.column_names
    print("No saved model, training new one...")
    return train_fresh_model()


def run_prediction(sample_url, forest, column_names):

    # step 1 - blacklist check using features.py function
    bl = is_domain_blacklisted(sample_url)
    if bl["is_blacklisted"]:
        return {
            "prediction":      1,
            "phishing_chance": 0.99,
            "safe_chance":     0.01,
            "confidence":      99.0,
            "risk_level":      "HIGH",
            "verdict":         "BLACKLISTED - CONFIRMED DANGEROUS",
            "features":        extract_features(sample_url),
        }

    # step 2 - whitelist check using features.py function
    wl = is_trusted_domain(sample_url)
    if wl["is_trusted"]:
        return {
            "prediction":      0,
            "phishing_chance": 0.02,
            "safe_chance":     0.98,
            "confidence":      98.0,
            "risk_level":      "MINIMAL",
            "verdict":         "SAFE - TRUSTED WEBSITE",
            "features":        extract_features(sample_url),
        }

    # step 3 - extract features and run through random forest
    features   = extract_features(sample_url)
    row        = [[features[col] for col in column_names]]
    phish_prob = forest.get_probability(row)[0]

    # step 4 - check known danger signals manually
    danger = 0
    danger += features.get("has_ip_in_url",            0) * 3
    danger += features.get("is_suspicious_tld",         0) * 3
    danger += features.get("has_brand_in_subdomain",    0) * 3
    danger += features.get("has_at_symbol",             0) * 2
    danger += features.get("has_punycode",              0) * 2
    danger += features.get("suspicious_word_count",     0) * 1
    danger += features.get("is_url_shortener",          0) * 1

    # step 5 - if no danger signs but ml says phishing - correct it
    if danger == 0 and features.get("has_https", 0) == 1 and phish_prob > 0.5:
        phish_prob = 0.20

    is_phishing = 1 if phish_prob >= 0.5 else 0
    confidence  = round(phish_prob * 100 if is_phishing else (1 - phish_prob) * 100, 2)

    if phish_prob >= 0.75:
        risk_level = "HIGH"
        verdict    = "PHISHING - VERY DANGEROUS"
    elif phish_prob >= 0.5:
        risk_level = "MEDIUM"
        verdict    = "SUSPICIOUS - BE CAREFUL"
    elif phish_prob >= 0.3:
        risk_level = "LOW"
        verdict    = "PROBABLY SAFE"
    else:
        risk_level = "MINIMAL"
        verdict    = "SAFE"

    return {
        "prediction":      is_phishing,
        "phishing_chance": round(phish_prob, 4),
        "safe_chance":     round(1 - phish_prob, 4),
        "confidence":      confidence,
        "risk_level":      risk_level,
        "verdict":         verdict,
        "features":        features,
    }


def make_case_id():
    import datetime
    import uuid
    now = datetime.datetime.now()
    tag = str(uuid.uuid4()).upper().split("-")[0]
    return "CASE-" + now.strftime("%Y%m%d") + "-" + tag