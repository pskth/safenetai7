"""
data/download_dataset.py -- Downloads a phishing email dataset to data/emails.csv.

Tries multiple public sources in order until one succeeds.
The final CSV will always have exactly two columns: text, label (phish / ham).

Run once before training:
    python data/download_dataset.py
"""

import csv
import os
import sys

try:
    import requests as _requests
    _USE_REQUESTS = True
except ImportError:
    _USE_REQUESTS = False

# ── Dataset source definitions ────────────────────────────────────────────────
SOURCES = [
    {
        "name": "Phishing Email Dataset (r3dhkr/PhishingEmailDataset)",
        "url": "https://raw.githubusercontent.com/r3dhkr/PhishingEmailDataset/main/Phishing_Email.csv",
        "text_col": "Email Text",
        "label_col": "Email Type",
        "phish_val": "Phishing Email",
        "ham_val": "Safe Email",
        "encoding": "utf-8",
    },
    {
        "name": "CEAS 2008 Mirror (shawhin/phishing-email-detection)",
        "url": "https://raw.githubusercontent.com/shawhin/phishing-email-detection/main/data/emails.csv",
        "text_col": "text",
        "label_col": "label",
        "phish_val": "phishing",
        "ham_val": "legitimate",
        "encoding": "utf-8",
    },
    {
        "name": "Spam Emails CSV (MWiechmann/email_spam_data)",
        "url": "https://raw.githubusercontent.com/MWiechmann/email_spam_data/main/emails.csv",
        "text_col": "message",
        "label_col": "label",
        "phish_val": "spam",
        "ham_val": "ham",
        "encoding": "utf-8",
    },
]

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "emails.csv")


def _download(url: str, dest: str) -> bool:
    """Download url to dest. Returns True on success."""
    try:
        print("  Downloading: " + url)
        if _USE_REQUESTS:
            resp = _requests.get(
                url,
                headers={"User-Agent": "PhishGuard/2.0"},
                timeout=30,
                verify=False,  # skip SSL verify on restrictive Windows envs
            )
            resp.raise_for_status()
            with open(dest, "wb") as f:
                f.write(resp.content)
        else:
            import urllib.request
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard/2.0"})
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r, \
                 open(dest, "wb") as f:
                f.write(r.read())
        return True
    except Exception as exc:
        print("  FAILED: " + str(exc)[:200])
        return False


def _convert(raw_path: str, source: dict, out_path: str) -> int:
    """
    Read raw_path, normalize columns to (text, label) using source mapping,
    and write to out_path. Returns number of rows written.
    """
    rows_written = 0
    text_col = source["text_col"]
    label_col = source["label_col"]
    phish_val = source["phish_val"]
    ham_val = source["ham_val"]
    enc = source.get("encoding", "utf-8")

    with open(raw_path, encoding=enc, errors="replace", newline="") as fin, \
         open(out_path, "w", encoding="utf-8", newline="") as fout:

        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames or []

        if text_col not in fieldnames or label_col not in fieldnames:
            print("  FAILED: Expected columns " + repr(text_col) + ", " + repr(label_col)
                  + " but found: " + str(fieldnames))
            return 0

        writer = csv.DictWriter(fout, fieldnames=["text", "label"])
        writer.writeheader()

        for row in reader:
            raw_label = str(row.get(label_col, "")).strip()
            if raw_label == phish_val:
                label = "phish"
            elif raw_label == ham_val:
                label = "ham"
            else:
                continue

            text = str(row.get(text_col, "")).strip()
            if not text:
                continue

            writer.writerow({"text": text, "label": label})
            rows_written += 1

    return rows_written


def download_dataset() -> None:
    """Try each source in order; stop after the first successful download + conversion."""
    raw_path = OUTPUT_PATH + ".raw"

    for source in SOURCES:
        print("\n[*] Trying: " + source["name"])
        if not _download(source["url"], raw_path):
            continue

        print("  Converting columns to (text, label)...")
        n = _convert(raw_path, source, OUTPUT_PATH)

        if n > 0:
            print("  OK: Wrote " + str(n) + " rows to " + OUTPUT_PATH)
            if os.path.exists(raw_path):
                os.remove(raw_path)
            return
        else:
            print("  FAILED: Conversion produced 0 rows -- trying next source.")
            if os.path.exists(raw_path):
                os.remove(raw_path)

    print("\nERROR: All sources failed.")
    print("Manually place a CSV with 'text' and 'label' columns at: " + OUTPUT_PATH)
    sys.exit(1)


if __name__ == "__main__":
    print("PhishGuard - Dataset Downloader")
    print("=" * 40)
    if _USE_REQUESTS:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    download_dataset()
