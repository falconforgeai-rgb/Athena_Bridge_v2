from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Any
import datetime

app = FastAPI(title="Athena CAP Bridge", version="2.0")

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
def healthcheck():
    return {"status": "alive", "time": datetime.datetime.utcnow().isoformat()}

@app.post("/cap")
async def receive_cap(request: Request):
    data = await request.json()
    print(f"Received CAP Record: {data.get('cap_id', 'unknown')}")
    return {"status": "CAP received", "timestamp": datetime.datetime.utcnow().isoformat()}
