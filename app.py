from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, Any
import hashlib, hmac, json, os, datetime, requests, uuid, time, asyncio, shutil, gzip
from collections import defaultdict
from pathlib import Path

app = FastAPI(title="Athena CAP Bridge v2.5", version="2.5")

# =========================================================
# Configuration
# =========================================================
SHARED_SECRET = os.getenv("ATHENA_SHARED_SECRET", "super_secret_shared_key_123!")
BRIDGE_URL = os.getenv("BRIDGE_URL", None)
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "10"))
LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = LOG_DIR / "bridge_log.jsonl"
MAX_LOG_LINES = int(os.getenv("MAX_LOG_LINES", "1000"))
ARCHIVE_DAYS = int(os.getenv("ARCHIVE_DAYS", "7"))

# =========================================================
# Rate Limiting
# =========================================================
rate_bucket = defaultdict(lambda: {"tokens": RATE_LIMIT, "timestamp": time.time()})

def check_rate_limit(ip: str) -> bool:
    bucket = rate_bucket[ip]
    now = time.time()
    elapsed = now - bucket["timestamp"]
    refill = elapsed * (RATE_LIMIT / 60.0)
    bucket["tokens"] = min(RATE_LIMIT, bucket["tokens"] + refill)
    bucket["timestamp"] = now
    if bucket["tokens"] >= 1:
        bucket["tokens"] -= 1
        return True
    return False

# =========================================================
# Models
# =========================================================
class CAPPayload(BaseModel):
    cap_id: str
    timestamp: str
    domain: str
    context_mode: str
    advisor_of_record: str
    outputs: Any
    cap_extensions: Any
    integrity: Any

# =========================================================
# Logging Helpers
# =========================================================
def rotate_logs():
    """Rotate and compress daily logs; prune old archives."""
    today = datetime.date.today().isoformat()
    archive_path = LOG_DIR / f"bridge_log_{today}.jsonl"

    # Rotate yesterday’s file
    if LOG_PATH.exists():
        mtime = datetime.date.fromtimestamp(LOG_PATH.stat().st_mtime)
        if mtime < datetime.date.today() and not archive_path.exists():
            shutil.move(str(LOG_PATH), str(archive_path))
            # Compress archive
            with open(archive_path, "rb") as src, gzip.open(f"{archive_path}.gz", "wb") as dst:
                shutil.copyfileobj(src, dst)
            archive_path.unlink()  # remove uncompressed

    # Prune archives older than ARCHIVE_DAYS
    for f in LOG_DIR.glob("bridge_log_*.jsonl.gz"):
        try:
            date_part = f.stem.replace("bridge_log_", "").replace(".jsonl", "")
            if (datetime.date.today() - datetime.date.fromisoformat(date_part)).days > ARCHIVE_DAYS:
                f.unlink()
        except Exception:
            continue

def prune_logs():
    """Keep only the last N lines."""
    try:
        if not LOG_PATH.exists():
            return
        lines = LOG_PATH.read_text().splitlines()
        if len(lines) > MAX_LOG_LINES:
            LOG_PATH.write_text("\n".join(lines[-MAX_LOG_LINES:]) + "\n")
    except Exception as e:
        print(f"[WARN] Log prune failed: {e}")

def log_json(event: str, data: dict):
    entry = {"event": event, "time": datetime.datetime.utcnow().isoformat(), **data}
    try:
        rotate_logs()
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
        prune_logs()
    except Exception as e:
        print(f"[ERROR] Logging failed: {e}")
    print(json.dumps(entry), flush=True)

# =========================================================
# Metrics
# =========================================================
metrics = {
    "start_time": datetime.datetime.utcnow().isoformat(),
    "caps_received": 0,
    "relay_success": 0,
    "relay_failed": 0,
    "rate_limited": 0,
}

@app.get("/healthz")
def healthz():
    uptime = (
        datetime.datetime.utcnow()
        - datetime.datetime.fromisoformat(metrics["start_time"])
    ).total_seconds()
    return {
        "status": "healthy",
        "uptime_seconds": uptime,
        "bridge_url": BRIDGE_URL or "none",
        "caps_received": metrics["caps_received"],
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }

@app.get("/metrics")
def get_metrics():
    return metrics

@app.get("/status")
def status():
    """Summarized operational health snapshot."""
    uptime = (
        datetime.datetime.utcnow()
        - datetime.datetime.fromisoformat(metrics["start_time"])
    ).total_seconds()
    return {
        "uptime_seconds": uptime,
        "rate_limit": RATE_LIMIT,
        "archive_days": ARCHIVE_DAYS,
        "bridge_url": BRIDGE_URL or "none",
        "logs_count": len(list(LOG_DIR.glob("bridge_log_*.jsonl.gz"))),
        "active_log_size_bytes": LOG_PATH.stat().st_size if LOG_PATH.exists() else 0,
    }

# =========================================================
# CAP Receiver
# =========================================================
@app.post("/cap")
async def receive_cap(request: Request, x_athena_signature: Optional[str] = Header(None)):
    ip = request.client.host or "unknown"

    if not check_rate_limit(ip):
        metrics["rate_limited"] += 1
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    computed_sig = hmac.new(SHARED_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if x_athena_signature != computed_sig:
        raise HTTPException(status_code=401, detail="Invalid signature")

    metrics["caps_received"] += 1
    trace_id = str(uuid.uuid4())
    log_data = {
        "trace_id": trace_id,
        "cap_id": payload.get("cap_id", "unknown"),
        "domain": payload.get("domain", "none"),
        "ip": ip,
    }

    relay_result = {"relay": "skipped"}
    if BRIDGE_URL:
        try:
            def forward():
                r = requests.post(f"{BRIDGE_URL}/cap", json=payload, timeout=10)
                return {"relay": "forwarded", "code": r.status_code, "body": r.text[:200]}

            relay_result = await asyncio.to_thread(forward)
            metrics["relay_success"] += 1
        except Exception as e:
            metrics["relay_failed"] += 1
            relay_result = {"relay": "failed", "error": str(e)}

    log_data["relay_result"] = relay_result
    log_json("cap_received", log_data)

    return {
        "status": "CAP validated",
        "trace_id": trace_id,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "relay_result": relay_result,
    }

# =========================================================
# Log Retrieval APIs
# =========================================================
@app.get("/logs")
def read_logs():
    """Retrieve last 20 structured logs + archive list."""
    current_logs = []
    if LOG_PATH.exists():
        with open(LOG_PATH, "r") as f:
            current_logs = [json.loads(line) for line in f.readlines()[-20:]]

    archives = [
        {"file": f.name, "modified": datetime.datetime.utcfromtimestamp(f.stat().st_mtime).isoformat()}
        for f in sorted(LOG_DIR.glob("bridge_log_*.jsonl.gz"), reverse=True)
    ]
    return {"current": current_logs, "archives": archives}

@app.get("/archive/{date}")
def get_archive(date: str):
    """Download archived log for specific date (ISO format YYYY-MM-DD)."""
    archive = LOG_DIR / f"bridge_log_{date}.jsonl.gz"
    if not archive.exists():
        raise HTTPException(status_code=404, detail=f"No archive found for {date}")
    return FileResponse(str(archive), media_type="application/gzip", filename=archive.name)

# =========================================================
# Root
# =========================================================
@app.get("/")
def root():
    return {
        "service": "Athena Bridge v2.5",
        "version": "2.5",
        "status": "operational",
        "docs": "/docs",
        "time": datetime.datetime.utcnow().isoformat(),
    }
