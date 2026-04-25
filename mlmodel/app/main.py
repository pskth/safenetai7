from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import email_scan, link_scan, doc_scan, unified_scan, offer_scan
import os

app = FastAPI(
    title="PhishGuard Scam Detection API",
    description="ML-powered phishing, scam email & link detection",
    version="2.0.0"
)

# CORS — restrict to your extension / frontend origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(email_scan.router, prefix="/scan/email", tags=["Email Scan"])
app.include_router(link_scan.router, prefix="/scan/link",  tags=["Phishing Link Scan"])
app.include_router(doc_scan.router,  prefix="/scan/doc",   tags=["Document Scan"])
app.include_router(unified_scan.router, prefix="/scan/unified", tags=["Unified Risk"])
app.include_router(offer_scan.router,  prefix="/scan/offer",   tags=["Offer Scam Detection"])


@app.get("/")
def read_root():
    return {"message": "PhishGuard API is running ✅", "version": "2.0.0"}


@app.get("/health")
def health_check():
    """Render uses this to verify the container is healthy."""
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    model_files = os.listdir(models_dir) if os.path.exists(models_dir) else []
    return {
        "status": "ok",
        "models_loaded": [f for f in model_files if f.endswith(".pkl")]
    }
