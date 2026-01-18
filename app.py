from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Any
import hashlib, hmac, json, os, datetime, requests, uuid, time, asyncio, shutil
from collections import defaultdict
from pathlib import Path

app = FastAPI(title="Athena CAP Bridge v2", version="2.4")

# =========================================================
# Configuration
# =========================================================
SHARED_SECRET = os.getenv("ATHENA_SHARED_SECRET", "super_secret_shared_key_123!")
BRIDGE_URL = os.getenv("BRIDGE_URL", None)
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "10"))  # requests/IP/min
LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = LOG_DIR / "bridge_log.jsonl"
MAX_LOG_LINES = int(os.getenv("MAX_LOG_LINES", "1000"))  # keep last 1000
ARCHIVE_DAYS = int(os.getenv("ARCHIVE_DAYS", "7"))  # keep archives for 7 days

# =========================================================
# Rate limiting
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
# Logging helpers
# =========================================================
def rotate_logs():
    """Rotate daily logs and prune archives older than ARCHIVE_DAYS."""
    today = datetime.date.today().isoformat()
    archive_path = LOG_DIR / f"bridge_log_{today}.jsonl"

    # If current log exists and not already archived, rotate
    if LOG_PATH.exists():
        # Only rotate if it's a new day and archive not yet created
        mtime = datetime.date.fromtimestamp(LOG_PATH.stat().st_mtime)
        if mtime < datetime.date.today():
            shutil.move(str(LOG_PATH), str(archive_path))

    # Clean old archives
    for f in LOG_DIR.glob("bridge_log_*.jsonl"):
        try:
            date_part = f.stem.replace("bridge_log_", "")
            if (datetime.date.today() - datetime.date.fromisoformat(date_part)).days > ARCHIVE_DAYS:
                f.unlink()
        except Exception:
            continue

def prune_logs():
    """Keep only the last N lines in the current log file."""
    try:
        if not LOG_PATH.exists():
            return
        lines = LOG_PATH.read_text().splitlines()
        if len(lines) > MAX_LOG_LINES:
            LOG_PATH.write_text("\n".join(lines[-MAX_LOG_LINES:]) + "\n")
    except Exception as e:
        print(f"[WARN] Failed to prune logs: {e}")

def log_json(event: str, data: dict):
    """Structured JSON logger."""
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
# Metrics & Health
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

@app.get("/")
def root():
    return {"status": "alive", "time": datetime.datetime.utcnow().isoformat()}

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
# Logs endpoint
# =========================================================
@app.get("/logs")
def read_logs():
    """Retrieve recent and archived logs summary."""
    current_logs = []
    if LOG_PATH.exists():
        with open(LOG_PATH, "r") as f:
            current_logs = [json.loads(line) for line in f.readlines()[-20:]]

    archives = [
        {"file": f.name, "modified": datetime.datetime.utcfromtimestamp(f.stat().st_mtime).isoformat()}
        for f in sorted(LOG_DIR.glob("bridge_log_*.jsonl"), reverse=True)
    ]
    return {"current": current_logs, "archives": archives}
