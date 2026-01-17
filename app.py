from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Any
import hashlib, hmac, json, os, datetime, requests, uuid, time
from collections import defaultdict
import asyncio

app = FastAPI(title="Athena CAP Bridge v2", version="2.1")

SHARED_SECRET = os.getenv("ATHENA_SHARED_SECRET", "super_secret_shared_key_123!")
BRIDGE_URL = os.getenv("BRIDGE_URL", None)
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "10"))  # max 10 requests per IP per minute

# In-memory token bucket for rate limiting
rate_bucket = defaultdict(lambda: {"tokens": RATE_LIMIT, "timestamp": time.time()})

def check_rate_limit(ip: str):
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

class CAPPayload(BaseModel):
    cap_id: str
    timestamp: str
    domain: str
    context_mode: str
    advisor_of_record: str
    outputs: Any
    cap_extensions: Any
    integrity: Any

def log_json(event: str, data: dict):
    """Structured JSON logger"""
    entry = {
        "event": event,
        "time": datetime.datetime.utcnow().isoformat(),
        **data,
    }
    os.makedirs("logs", exist_ok=True)
    with open("logs/bridge_log.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")

@app.get("/")
def health():
    return {
        "status": "alive",
        "time": datetime.datetime.utcnow().isoformat(),
        "bridge_url": BRIDGE_URL or "none",
    }

@app.post("/cap")
async def receive_cap(request: Request, x_athena_signature: Optional[str] = Header(None)):
    ip = request.client.host

    # Rate limiting
    if not check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Verify HMAC signature
    mac = hmac.new(SHARED_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if x_athena_signature != mac:
        raise HTTPException(status_code=401, detail="Invalid signature")

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
            r = requests.post(f"{BRIDGE_URL}/cap", json=payload, timeout=10)
            relay_result = {
                "relay": "forwarded",
                "code": r.status_code,
                "body": r.text[:300],
            }
        except Exception as e:
            relay_result = {"relay": "failed", "error": str(e)}

    log_data["relay_result"] = relay_result
    log_json("cap_received", log_data)

    return {
        "status": "CAP validated",
        "trace_id": trace_id,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "relay_result": relay_result,
    }

@app.get("/logs")
def read_logs():
    """Debug endpoint to retrieve last 10 log entries"""
    path = "logs/bridge_log.jsonl"
    if not os.path.exists(path):
        return {"logs": []}
    with open(path, "r") as f:
        lines = f.readlines()[-10:]
    return {"logs": [json.loads(line) for line in lines]}
