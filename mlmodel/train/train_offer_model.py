"""
Train a custom ML model for detecting fake internship/job offers.
Uses hand-engineered scam-detection features combined with TF-IDF.
"""

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
from scipy.sparse import hstack, csr_matrix
import joblib
import os
import re
import json

# ---------------------------------------------------------------------------
# Scam-pattern detectors (context-aware)
# ---------------------------------------------------------------------------

# Payment demand: "pay fee/deposit" — NOT "stipend Rs X"
PAYMENT_DEMAND_PATTERNS = [
    r'\bpay\b.*\b(fee|deposit|charge|amount|registration|processing)\b',
    r'\b(fee|deposit|charge|registration|processing)\b.*\bpay\b',
    r'\b(fee|deposit|charge)\s*[:=]?\s*(rs|₹|inr)\s*\d+',
    r'(rs|₹|inr)\s*\d+.{0,30}\b(fee|deposit|charge|registration|processing)\b',
    r'\btransfer\s*(rs|₹|inr)\s*\d+',
    r'\bpay\s*(rs|₹|inr)\s*\d+',
    r'\bpay\s*via\b', r'\bpay\s*now\b', r'\bpay\s*here\b',
    r'\bpay\s*immediately\b', r'\bpay\s*to\b',
    r'\bupi\s*(id|:)\b', r'@(paytm|ybl|oksbi|okicici|okaxis)\b',
    r'\bgpay\s*to\b', r'\bphonepe\s*to\b', r'\bgoogle\s*pay\s*to\b',
    r'\bpurchase\b.*\b(kit|course|material)\b',
    r'\bbuy\b.*\b(kit|course|material)\b',
    r'\b(refundable|non-refundable)\s*(deposit|fee)\b',
]

URGENCY_PATTERNS = [
    r'within\s+\d+\s*hour', r'within\s+\d+\s*minute',
    r'\bexpire[s]?\b', r'\bexpir(ing|ed)\b',
    r'\blast\s*chance\b', r'\blast\s*reminder\b', r'\bfinal\s*reminder\b',
    r'\bhurry\b', r'\bdon.t\s*miss\b', r'\bact\s*now\b', r'\bact\s*fast\b',
    r'\bfilling\s*fast\b', r'\bonly\s*\d+\s*(seats?|slots?|left)\b',
    r'(slot|offer|spot)\s*(will\s*be|about\s*to\s*be)\s*(given|released|cancelled|expire)',
    r'\b(last|final)\s*(notification|notice|warning)\b',
    r'\basap\b', r'\bimmediately\b',
]

SUSPICIOUS_LINK_PATTERNS = [
    r'bit\.ly', r'forms\.gle', r'tinyurl', r'shorturl',
    r'https?://[^\s]*\.(xyz|info|co\.in|online|site|top|club|cc)\b',
]

WHATSAPP_ONLY_PATTERNS = [
    r'(contact|reply|respond|message)\s*(only\s*)?(on|via)\s*whatsapp',
    r'whatsapp\s*(only|us|me|queries)',
    r'(dm|message)\s*(us|me)\s*(on\s*)?(whatsapp|insta)',
    r'details\s*(will\s*be\s*)?(shared|sent)\s*(only\s*)?after\s*payment',
    r'whatsapp\s*:\s*\+91',
    r'(call|whatsapp)\s*:\s*\+?91',
]

TOO_GOOD_PATTERNS = [
    r'no\s*(experience|skills?|coding|interview)\s*(needed|required)',
    r'guaranteed\s*(placement|job|offer)',
    r'100\s*%\s*placement', r'zero\s*experience',
    r'money\s*back\s*guarantee',
    r'free\s*(macbook|laptop|iphone)',
    r'all\s*expenses\s*paid',
    r'any\s*(degree|branch|year)\s*(accepted|eligible|welcome)',
]

CREDENTIAL_PATTERNS = [
    r'\b(aadhaar|aadhar|pan\s*card|passport)\s*(number|copy|details)\b',
    r'\bbank\s*(account|details)\b',
    r'\botp\b', r'\bpassword\b',
]

PRESSURE_PATTERNS = [
    r'share\s*(this|with)\s*\d+\s*friend',
    r'share\s*(screenshot|receipt|proof)\b',
    r'(will\s*be|get)\s*(deleted|removed|cancelled)',
    r'no\s*further\s*reminders?',
    r'this\s*(is\s*)?not\s*a\s*scam',
    r'(send|share)\s*(payment\s*)?proof',
]

LEGIT_INDICATORS = [
    r'\b\w+@(google|microsoft|amazon|flipkart|razorpay|swiggy|zomato|uber|adobe|oracle|infosys|tcs|wipro|samsung|qualcomm|jpmorgan|mckinsey|deloitte|atlassian|phonepe|paytm|goldman|cognizant|accenture|capgemini|kpmg|ola)\.\w+',
    r'\b(docusign|hireright|sterling|first\s*advantage|adobe\s*sign)\b',
    r'\bbackground\s*(check|verification)\b',
    r'\b(hr\s*portal|careers?\s*portal|onboarding\s*portal|taleo)\b',
    r'\boffer\s*letter\s*(will\s*be\s*)?(sent|shared|emailed|dispatched)\b',
    r'\bno\s*fees?\s*(are\s*)?(associated|charged|required|at\s*any\s*stage)\b',
    r'\bnever\s*(charge[s]?|request[s]?\s*payment)\b',
    r'\bpre-joining\b',
    r'\bacademic\s*transcripts?\b',
]


def count_matches(text, patterns):
    t = text.lower()
    return sum(1 for p in patterns if re.search(p, t))


def has_fee_demand(text):
    """Check if text demands payment of a FEE (not just mentioning stipend)."""
    return count_matches(text, PAYMENT_DEMAND_PATTERNS) >= 1


def extract_features(text):
    t = text.lower()
    f = {}
    f['has_fee_demand'] = 1 if has_fee_demand(text) else 0
    f['payment_demand_score'] = count_matches(text, PAYMENT_DEMAND_PATTERNS)
    f['urgency_score'] = count_matches(text, URGENCY_PATTERNS)
    f['suspicious_link_score'] = count_matches(text, SUSPICIOUS_LINK_PATTERNS)
    f['whatsapp_only_score'] = count_matches(text, WHATSAPP_ONLY_PATTERNS)
    f['too_good_score'] = count_matches(text, TOO_GOOD_PATTERNS)
    f['credential_score'] = count_matches(text, CREDENTIAL_PATTERNS)
    f['pressure_score'] = count_matches(text, PRESSURE_PATTERNS)
    f['legit_score'] = count_matches(text, LEGIT_INDICATORS)
    f['message_length'] = min(len(text), 2000)  # cap to prevent domination
    f['word_count'] = min(len(text.split()), 400)
    f['has_email'] = 1 if re.search(r'\b\w+@\w+\.\w+', text) else 0
    f['exclamation_count'] = min(text.count('!'), 10)
    f['caps_ratio'] = round(sum(1 for c in text if c.isupper()) / max(len(text), 1), 4)
    f['url_count'] = len(re.findall(r'https?://\S+', text))
    f['phone_count'] = len(re.findall(r'\+91[\s-]?\d{10}|\b\d{10}\b', text))
    # Composite scam score
    f['scam_signal'] = (f['has_fee_demand'] * 3 + f['urgency_score'] +
                        f['suspicious_link_score'] * 2 + f['whatsapp_only_score'] * 2 +
                        f['too_good_score'] * 2 + f['credential_score'] * 2 +
                        f['pressure_score'] * 2 - f['legit_score'] * 3 - f['has_email'] * 2)
    return f


def get_red_flags(text):
    flags = []
    if has_fee_demand(text):
        flags.append("Payment or fee demanded from candidate")
    if count_matches(text, URGENCY_PATTERNS) >= 1:
        flags.append("Urgency/pressure language used")
    if count_matches(text, SUSPICIOUS_LINK_PATTERNS) >= 1:
        flags.append("Suspicious or shortened links found")
    if count_matches(text, WHATSAPP_ONLY_PATTERNS) >= 1:
        flags.append("Communication restricted to WhatsApp only")
    if count_matches(text, TOO_GOOD_PATTERNS) >= 1:
        flags.append("Unrealistic promises (no experience needed, guaranteed placement)")
    if count_matches(text, CREDENTIAL_PATTERNS) >= 1:
        flags.append("Requests for sensitive personal documents")
    if count_matches(text, PRESSURE_PATTERNS) >= 1:
        flags.append("Social pressure tactics detected")
    if not re.search(r'\b\w+@\w+\.\w+', text) and len(text) > 150 and has_fee_demand(text):
        flags.append("No official email address provided")
    return flags


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+", " URL ", text)
    text = re.sub(r"\+91[\s-]?\d{10}", " PHONE ", text)
    text = re.sub(r"\b\w+@\w+\.\w+\b", " EMAIL ", text)
    text = re.sub(r"[₹$]?\s*\d[\d,]*", " NUM ", text)
    text = re.sub(r"[^a-zA-Z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def main():
    # Load both datasets
    df1 = pd.read_csv("datasets/offer_messages.csv")
    df2 = pd.read_csv("datasets/offer_messages_extra.csv")
    df3 = pd.read_csv("datasets/offer_messages_generated.csv")
    df = pd.concat([df1, df2, df3], ignore_index=True)
    df.dropna(inplace=True)
    df = df.drop_duplicates(subset=['message'])
    print(f"Loaded {len(df)} messages")
    print(f"Fake: {(df['label']==0).sum()}, Legit: {(df['label']==1).sum()}\n")

    # Extract features
    print("Extracting features...")
    feat_dicts = df['message'].apply(extract_features).tolist()
    feat_df = pd.DataFrame(feat_dicts)
    feat_names = list(feat_df.columns)
    X_custom = csr_matrix(feat_df.values)

    # TF-IDF
    df['cleaned'] = df['message'].apply(clean_text)
    tfidf = TfidfVectorizer(max_features=2000, ngram_range=(1, 2))
    X_tfidf = tfidf.fit_transform(df['cleaned'])

    X = hstack([X_custom, X_tfidf])
    y = df['label']
    print(f"Features: {X.shape[1]} (Custom: {len(feat_names)}, TF-IDF: {X_tfidf.shape[1]})\n")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=['Fake', 'Legit']))

    cv = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    print(f"CV: {cv.mean():.4f} (+/- {cv.std():.4f})\n")

    imp = np.abs(model.coef_[0][:len(feat_names)])
    for i in np.argsort(imp)[::-1][:10]:
        print(f"  {feat_names[i]}: {imp[i]:.4f}")

    os.makedirs("app/models", exist_ok=True)
    joblib.dump(model, "app/models/offer_model.pkl")
    joblib.dump(tfidf, "app/models/offer_tfidf.pkl")
    with open("app/models/offer_metadata.json", "w") as f:
        json.dump({"custom_feature_names": feat_names}, f, indent=2)
    print("\nModel saved!\n")

    # Sanity check
    print("=" * 60)
    print("SANITY CHECK")
    print("=" * 60)
    tests = [
        ("Hi Rahul, Good news! You've been selected for the Software Development Internship at NexaByte Solutions. "
         "Details: Duration: 3 months, Stipend: Rs 15000/month, Start Date: 10 May 2026. Please confirm your acceptance "
         "here on WhatsApp within 24 hours so we can proceed with your onboarding. Congrats! Anjali Sharma, HR Team",
         "Legit offer (no payment, just confirm)"),
        ("Welcome to the Google Summer Internship Program", "Short legit"),
        ("Hi Rahul, This is Priya Mehta from the HR team at NexaByte Solutions. You have been selected for Software "
         "Development Intern. Duration: 3 months, Stipend: Rs 15000/month, Start: 10 May 2026, Remote. You will receive "
         "a formal offer letter on your registered email. Kindly confirm by replying. Best regards, Priya Mehta, HR Team",
         "Professional legit offer"),
        ("Pay Rs 2999 registration fee to confirm your internship. Limited seats. WhatsApp only +91-9876543210",
         "Obvious scam"),
    ]
    for msg, desc in tests:
        feats = extract_features(msg)
        Xc = csr_matrix(pd.DataFrame([feats])[feat_names].values)
        Xt = tfidf.transform([clean_text(msg)])
        Xcomb = hstack([Xc, Xt])
        pred = model.predict(Xcomb)[0]
        prob = model.predict_proba(Xcomb)[0]
        conf = prob[0] * 100 if pred == 0 else prob[1] * 100
        flags = get_red_flags(msg)
        print(f"\n[{desc}] -> {'FAKE' if pred==0 else 'LEGIT'} ({conf:.1f}%)")
        if flags:
            print(f"  Red flags: {flags}")


if __name__ == "__main__":
    main()
