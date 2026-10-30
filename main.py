
from fastapi import FastAPI, Request
from datetime import datetime, timezone

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/callback")
async def callback(request: Request):
    payload = await request.json()

    print({
        "received_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload
    })

    return {"status": "accepted"}
