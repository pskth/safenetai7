# PhishGuard — Gmail Pub/Sub Ingestion Layer (Phase 1)

> **Goal of this phase:** Prove the end-to-end plumbing.  
> Email arrives → app is notified → email is fetched → Gmail label is applied.  
> No ML, no scoring, no SMTP — Gmail API only.

---

## Project Structure

```
phishguard/
├── main.py            # FastAPI app — Pub/Sub webhook listener
├── gmail_client.py    # OAuth 2.0 auth + Gmail API resource factory
├── label_manager.py   # Creates and applies the [PhishGuard] label
├── watch_manager.py   # Registers the Gmail Pub/Sub inbox watch
├── config.py          # All env var definitions (single source of truth)
├── requirements.txt
└── .env               # Your secrets — never commit this
```

---

## Step 1 — Google Cloud Prerequisites

> Complete these steps **once** in the Google Cloud Console before running the app.

### 1.1 Create a Project and Enable APIs

1. Go to [https://console.cloud.google.com/](https://console.cloud.google.com/) and create a new project (e.g. `phishguard-dev`).
2. In **APIs & Services → Library**, enable:
   - **Gmail API**
   - **Cloud Pub/Sub API**

### 1.2 Create OAuth 2.0 Credentials

1. Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
2. Choose **Application type: Desktop app**.
3. Name it `PhishGuard Local`.
4. Download the JSON and save it as `credentials.json` in the project root.

### 1.3 Configure the OAuth Consent Screen

1. Go to **APIs & Services → OAuth consent screen**.
2. Set User Type to **External** (for testing with your own account).
3. Add your Gmail address as a **Test User**.
4. Add the scope `https://www.googleapis.com/auth/gmail.modify`.

### 1.4 Create the Pub/Sub Topic

```bash
gcloud pubsub topics create phishguard-inbound --project=YOUR_PROJECT_ID
```

Or via the Console: **Pub/Sub → Topics → Create Topic**, name it `phishguard-inbound`.

### 1.5 Grant Gmail Publish Rights on the Topic

Gmail needs permission to publish to your topic. Run:

```bash
gcloud pubsub topics add-iam-policy-binding phishguard-inbound \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
  --role="roles/pubsub.publisher" \
  --project=YOUR_PROJECT_ID
```

### 1.6 Create the Pub/Sub Push Subscription

Replace `YOUR_PUBLIC_URL` with your ngrok URL (get this in Step 3):

```bash
gcloud pubsub subscriptions create phishguard-sub \
  --topic=phishguard-inbound \
  --push-endpoint=https://YOUR_PUBLIC_URL/webhook/gmail \
  --ack-deadline=30 \
  --project=YOUR_PROJECT_ID
```

Or via the Console: **Pub/Sub → Subscriptions → Create Subscription**, choose Push delivery and enter the webhook URL.

---

## Step 2 — Local Setup

### 2.1 Install dependencies

```powershell
# Create a virtual environment (recommended)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install packages
pip install -r requirements.txt
```

### 2.2 Configure environment variables

Copy `.env` and fill in your values:

```
GOOGLE_CLIENT_CREDENTIALS_PATH=credentials.json
GOOGLE_TOKEN_PATH=token.json
PUBSUB_TOPIC_NAME=projects/YOUR_PROJECT_ID/topics/phishguard-inbound
GMAIL_USER_ID=me
TEST_TRIGGER_WORD=ABCDEFGH
```

---

## Step 3 — First Run (OAuth Consent)

Start the server once to trigger the browser-based OAuth flow:

```powershell
uvicorn main:app --reload --port 8080
```

A browser window will open asking you to log in with Google and grant Gmail access.  
After consent, `token.json` is written to disk and the app registers the Gmail watch automatically.

> **Watch expiry:** The Gmail watch lasts **7 days**.  
> You must restart the app (or call `register_watch()`) before then to renew it.  
> Production systems should schedule a daily renewal job.

---

## Step 4 — Expose Locally with ngrok

In a **separate terminal**:

```powershell
ngrok http 8080
```

Copy the `https://xxxx.ngrok-free.app` URL and update your Pub/Sub push subscription endpoint:

```bash
gcloud pubsub subscriptions modify-push-config phishguard-sub \
  --push-endpoint=https://xxxx.ngrok-free.app/webhook/gmail \
  --project=YOUR_PROJECT_ID
```

---

## Step 5 — End-to-End Test

1. Send an email **to the watched Gmail address** with the word `ABCDEFGH` anywhere in the **subject line**.
2. Watch the terminal — within a few seconds you should see:

```
INFO phishguard: 📬 Notification received for you@gmail.com | historyId=...
INFO phishguard: --- Checking message ID: 18xxxxxxx ---
INFO phishguard: Message 18xxx | Subject: 'ABCDEFGH test' | Trigger in subject: True ...
INFO phishguard: 🎯 Trigger word 'ABCDEFGH' found — applying [PhishGuard] label...
INFO phishguard: ✅ Applied label '[PhishGuard]' to message 18xxx
```

3. Open Gmail → the email should now carry the **[PhishGuard]** label in the left sidebar.

---

## Adding Pipeline Stages (Phase 2+)

Each file has clearly marked `# Phase 2:` comments showing where to plug in:

| File | Extension point |
|------|----------------|
| `main.py` | Replace `_process_message` trigger word check with your scoring call |
| `label_manager.py` | Add more label names (e.g. `[PhishGuard-High]`) |
| `watch_manager.py` | Add watch renewal scheduling |
| `config.py` | Add new env vars (API keys, model endpoints, etc.) |

---

## Common Issues

| Symptom | Fix |
|---------|-----|
| `FileNotFoundError: credentials.json` | Download OAuth credentials from Cloud Console and place in project root |
| `HttpError 403` on watch registration | Ensure `gmail-api-push@system.gserviceaccount.com` has `pubsub.publisher` role |
| Webhook not receiving requests | Verify ngrok is running and Pub/Sub subscription URL matches `https://.../webhook/gmail` |
| Label not appearing | Check the app logs for `❌ Failed to apply label` — may be a scope issue; delete `token.json` and re-authenticate |
| `ValueError: PUBSUB_TOPIC_NAME is not set` | Fill in `PUBSUB_TOPIC_NAME` in `.env` with the full topic path |
