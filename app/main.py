from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.api import logs, incidents
from app.storage.database import engine
from app.models.model import Base

Base.metadata.create_all(bind=engine)

app = FastAPI(title="InsightGuard Backend")

# Allow the dashboard (opened from file:// or localhost) to talk to the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router)
app.include_router(incidents.router)


@app.get("/")
def healthcheck():
    return {"status": "ok", "service": "InsightGuard Backend"}


class ChatRequest(BaseModel):
    message: str


@app.post("/api/chat")
def oracle_chat(payload: ChatRequest):
    """
    Minimal AI Oracle placeholder for the dashboard chat panel.
    This can later be wired to a real LLM or analysis engine.
    """
    msg = payload.message.strip()
    if not msg:
        reply = "No command received. Try: 'Identify high risk IPs'."
    else:
        reply = (
            f"InsightGuard has received your query: '{msg}'. "
            "Rule‑based and anomaly detectors are scanning recent events. "
            "Integrate a real AI model here for deeper analysis."
        )
    return {"reply": reply}
