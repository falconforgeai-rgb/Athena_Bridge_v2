from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Any
import hashlib, hmac, json, os, datetime, requests, uuid

app = FastAPI(title="Athena CAP Bridge v2", version="2.0")

SHARED_SECRET = os.getenv("ATHENA_SHARED_SECRET", "super_secret_shared_key_123!")
BRIDGE_URL = os.getenv("BRIDGE_URL", None)

class CAPPayload(BaseModel):
    cap_id: str
    timestamp: str
    domain: str
    context_mode: str
    advisor_of_record: str
    outputs: Any
    cap_extensions: Any
    integrity: Any

@app.get("/")
def health():
    return {
        "status": "alive",
        "time": datetime.datetime.utcnow().isoformat(),
        "bridge_url": BRIDGE_URL or "none",
    }

@app.post("/cap")
async def receive_cap(request: Request, x_athena_signature: Optional[str] = Header(None)):
    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Validate HMAC
    mac = hmac.new(SHARED_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if x_athena_signature != mac:
        raise HTTPException(status_code=401, detail="Invalid signature")

    trace_id = str(uuid.uuid4())
    log_entry = {
        "trace_id": trace_id,
        "received_at": datetime.datetime.utcnow().isoformat(),
        "cap_id": payload.get("cap_id"),
        "domain": payload.get("domain"),
    }

    # Optional relay to another service (Athena Core or Validator)
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

    log_entry["relay_result"] = relay_result

    # Log persistently
    os.makedirs("logs", exist_ok=True)
    with open("logs/bridge_log.txt", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return {
        "status": "CAP validated",
        "trace_id": trace_id,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "relay_result": relay_result,
    }
