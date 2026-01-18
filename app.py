from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Any
import hashlib, hmac, json, os, datetime, requests, uuid, time, asyncio
from collections import defaultdict

app = FastAPI(title="Athena CAP Bridge v2", version="2.2")

# =========================================================
# Configuration
# =========================================================
SHARED_SECRET = os.getenv("ATHENA_SHARED_SECRET", "super_secret_shared_key_123!")
BRIDGE_URL = os.getenv("BRIDGE_URL", None)
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "10"))  # per IP per minute
LOG_PATH = os.getenv("LOG_PATH", "/data/bridge_log.jsonl")

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

# =========================================================
# Rate limiting (token bucket per IP)
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
# Data model
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
def log_json(event: str, data: dict):
    """Structured JSON logger (file + stdout for Render visibility)."""
    entry = {
        "event": event,
        "time": datetime.datetime.utcnow().isoformat(),
        **data,
    }
    line = json.dumps(entry)
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)

# =========================================================
# Health & metrics
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
# Core CAP receiver
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

    # HMAC validation
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
            async def forward():
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
# Log retrieval endpoint
# =========================================================
@app.get("/logs")
def read_logs():
    """Retrieve the last 20 structured log entries."""
    if not os.path.exists(LOG_PATH):
        return {"logs": []}
    with open(LOG_PATH, "r") as f:
        lines = f.readlines()[-20:]
    return {"logs": [json.loads(line) for line in lines]}
