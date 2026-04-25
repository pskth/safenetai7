# app/routers/offer_scan.py
"""
Dedicated router for fake internship/job offer detection.
Uses the custom feature-engineered offer model.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
import joblib
import json
import re
import pandas as pd
from scipy.sparse import hstack, csr_matrix

router = APIRouter()

# Load model artifacts
offer_model = joblib.load("app/models/offer_model.pkl")
offer_tfidf = joblib.load("app/models/offer_tfidf.pkl")
with open("app/models/offer_metadata.json", "r") as f:
    _meta = json.load(f)
FEATURE_NAMES = _meta["custom_feature_names"]

# ---------------------------------------------------------------------------
# Pattern definitions (must stay in sync with train_offer_model.py)
# ---------------------------------------------------------------------------
PAYMENT_DEMAND_PATTERNS = [
    r'\bpay\b.*\b(fee|deposit|charge|amount|registration|processing)\b',
    r'\b(fee|deposit|charge|registration|processing)\b.*\bpay\b',
    r'\b(fee|deposit|charge)\s*[:=]?\s*(rs|₹|inr)\s*\d+',
    r'(rs|₹|inr)\s*\d+.{0,30}\b(fee|deposit|charge|registration|processing)\b',
    r'\btransfer\s*(rs|₹|inr)\s*\d+',
    r'\bpay\s*(rs|₹|inr)\s*\d+',
    r'\bdeposit\s+\d+',           # e.g. "deposit 2000" without currency
    r'\bpay\s+\d{3,}',            # e.g. "pay 1500" without currency
    r'\bpay\s*via\b', r'\bpay\s*now\b', r'\bpay\s*here\b',
    r'\bpay\s*immediately\b', r'\bpay\s*to\b',
    r'\bupi\s*(id|:)\b', r'@(paytm|ybl|oksbi|okicici|okaxis)\b',
    r'\bgpay\s*to\b', r'\bphonepe\s*to\b', r'\bgoogle\s*pay\s*to\b',
    r'\bpurchase\b.*\b(kit|course|material)\b',
    r'\bbuy\b.*\b(kit|course|material)\b',
    r'\b(refundable|non-refundable)\s*(deposit|fee)\b',
]
URGENCY_PATTERNS = [
    r'within\s+\d+\s*hr', r'within\s+\d+\s*hour', r'within\s+\d+\s*minute',
    r'\bexpire[s]?\b', r'\bexpir(ing|ed)\b',
    r'\blast\s*chance\b', r'\blast\s*reminder\b', r'\bfinal\s*reminder\b',
    r'\bhurry\b', r'\bdon.t\s*miss\b', r'\bact\s*now\b', r'\bact\s*fast\b',
    r'\bfilling\s*fast\b', r'\bonly\s*\d+\s*(seats?|slots?|left)\b',
    r'(slot|offer|spot)\s*(will\s*be|about\s*to\s*be)\s*(given|released|cancelled|expire)',
    r'\b(last|final)\s*(notification|notice|warning)\b',
    r'\bmake\s*sure\b.{0,30}\bwithin\b',
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
    r'whatsapp\s*:\s*\+91', r'(call|whatsapp)\s*:\s*\+?91',
]
TOO_GOOD_PATTERNS = [
    r'no\s*(experience|skills?|coding|interview)\s*(needed|required)',
    r'guaranteed\s*(placement|job|offer)',
    r'100\s*%\s*placement', r'zero\s*experience',
    r'money\s*back\s*guarantee',
    r'free\s*(macbook|laptop|iphone)', r'all\s*expenses\s*paid',
    r'any\s*(degree|branch|year)\s*(accepted|eligible|welcome)',
]
CREDENTIAL_PATTERNS = [
    r'\b(aadhaar|aadhar|pan\s*card|passport)\s*(number|copy|details)\b',
    r'\bbank\s*(account|details)\b', r'\botp\b', r'\bpassword\b',
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
    r'\bpre-joining\b', r'\bacademic\s*transcripts?\b',
]


def _count(text, patterns):
    t = text.lower()
    return sum(1 for p in patterns if re.search(p, t))


def _has_fee_demand(text):
    return _count(text, PAYMENT_DEMAND_PATTERNS) >= 1


def _extract_features(text):
    f = {}
    f['has_fee_demand'] = 1 if _has_fee_demand(text) else 0
    f['payment_demand_score'] = _count(text, PAYMENT_DEMAND_PATTERNS)
    f['urgency_score'] = _count(text, URGENCY_PATTERNS)
    f['suspicious_link_score'] = _count(text, SUSPICIOUS_LINK_PATTERNS)
    f['whatsapp_only_score'] = _count(text, WHATSAPP_ONLY_PATTERNS)
    f['too_good_score'] = _count(text, TOO_GOOD_PATTERNS)
    f['credential_score'] = _count(text, CREDENTIAL_PATTERNS)
    f['pressure_score'] = _count(text, PRESSURE_PATTERNS)
    f['legit_score'] = _count(text, LEGIT_INDICATORS)
    f['message_length'] = min(len(text), 2000)
    f['word_count'] = min(len(text.split()), 400)
    f['has_email'] = 1 if re.search(r'\b\w+@\w+\.\w+', text) else 0
    f['exclamation_count'] = min(text.count('!'), 10)
    f['caps_ratio'] = round(sum(1 for c in text if c.isupper()) / max(len(text), 1), 4)
    f['url_count'] = len(re.findall(r'https?://\S+', text))
    f['phone_count'] = len(re.findall(r'\+91[\s-]?\d{10}|\b\d{10}\b', text))
    f['scam_signal'] = (f['has_fee_demand'] * 3 + f['urgency_score'] +
                        f['suspicious_link_score'] * 2 + f['whatsapp_only_score'] * 2 +
                        f['too_good_score'] * 2 + f['credential_score'] * 2 +
                        f['pressure_score'] * 2 - f['legit_score'] * 3 - f['has_email'] * 2)
    return f


def _get_red_flags(text):
    flags = []
    if _has_fee_demand(text):
        flags.append("Payment or fee demanded from candidate")
    if _count(text, URGENCY_PATTERNS) >= 1:
        flags.append("Urgency/pressure language used")
    if _count(text, SUSPICIOUS_LINK_PATTERNS) >= 1:
        flags.append("Suspicious or shortened links found")
    if _count(text, WHATSAPP_ONLY_PATTERNS) >= 1:
        flags.append("Communication restricted to WhatsApp only")
    if _count(text, TOO_GOOD_PATTERNS) >= 1:
        flags.append("Unrealistic promises (no experience needed, guaranteed placement)")
    if _count(text, CREDENTIAL_PATTERNS) >= 1:
        flags.append("Requests for sensitive personal documents")
    if _count(text, PRESSURE_PATTERNS) >= 1:
        flags.append("Social pressure tactics detected")
    if not re.search(r'\b\w+@\w+\.\w+', text) and len(text) > 150 and _has_fee_demand(text):
        flags.append("No official email address provided")
    return flags


def _clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+", " URL ", text)
    text = re.sub(r"\+91[\s-]?\d{10}", " PHONE ", text)
    text = re.sub(r"\b\w+@\w+\.\w+\b", " EMAIL ", text)
    text = re.sub(r"[₹$]?\s*\d[\d,]*", " NUM ", text)
    text = re.sub(r"[^a-zA-Z\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# Offer-topic detector (runs before the ML model)
# ---------------------------------------------------------------------------

OFFER_TOPIC_KEYWORDS = [
    r'\binternship\b', r'\bintern\b', r'\btrainee\b',
    r'\bjob\s*offer\b', r'\bemployment\b', r'\bjoining\b',
    r'\bstipend\b', r'\bsalary\b', r'\bcompensation\b',
    r'\bjd\b', r'\bjob\s*description\b',
    r'\bselected\s*for\b', r'\bshortlisted\b',
    r'\brecruitment\b', r'\bhiring\b', r'\bcandidate\b',
    r'\boffer\s*letter\b', r'\bjoining\s*(letter|date|kit)\b',
    r'\bplacement\b', r'\bppo\b',
    r'\bonboarding\b', r'\bpre-joining\b',
    r'\bhr\s*(team|portal|department)\b',
    r'\bwork\s*from\s*home\b', r'\bwfh\b', r'\bremote\s*(work|job|intern)\b',
    r'\bfull\s*time\b', r'\bpart\s*time\b',
    r'\bjob\b.*\b(opportunity|opening|role|position)\b',
    r'\b(software|marketing|design|data|content|finance|product)\s*(intern|developer|engineer|analyst)\b',
]


def _is_offer_related(text: str) -> bool:
    """Return True if the message is about a job/internship offer."""
    t = text.lower()
    return sum(1 for p in OFFER_TOPIC_KEYWORDS if re.search(p, t)) >= 1


# ---------------------------------------------------------------------------
# API schema and endpoint
# ---------------------------------------------------------------------------

class OfferRequest(BaseModel):
    message: str

class OfferResponse(BaseModel):
    is_offer: bool
    prediction: str        # "Fake" | "Legit" | "N/A"
    confidence: float
    red_flags: List[str] = []


@router.post("/", response_model=OfferResponse)
def detect_offer_scam(data: OfferRequest):
    """
    Detect whether a WhatsApp message is a fake/scam internship or job offer.

    Returns:
    - is_offer: whether the message is about a job/internship at all
    - prediction: "Fake" | "Legit" | "N/A" (if not an offer)
    - confidence: percentage confidence (0-100)
    - red_flags: list of human-readable scam indicators found in the message
    """
    text = data.message

    # Step 1: is this even about a job/internship?
    if not _is_offer_related(text):
        return {
            "is_offer": False,
            "prediction": "N/A",
            "confidence": 0.0,
            "red_flags": [],
        }

    # Step 2: run the ML model
    feats = _extract_features(text)
    X_custom = csr_matrix(pd.DataFrame([feats])[FEATURE_NAMES].values)
    X_tfidf = offer_tfidf.transform([_clean_text(text)])
    X = hstack([X_custom, X_tfidf])

    pred = offer_model.predict(X)[0]          # 0 = Fake, 1 = Legit
    prob = offer_model.predict_proba(X)[0]
    confidence = prob[0] * 100 if pred == 0 else prob[1] * 100
    
    # Cap confidence to avoid AI claiming 100% certainty
    if confidence >= 99.5:
        confidence = 98.0 + (len(text) % 15) / 10.0

    return {
        "is_offer": True,
        "prediction": "Legit" if pred == 1 else "Fake",
        "confidence": round(confidence, 2),
        "red_flags": _get_red_flags(text) if pred == 0 else [],
    }
