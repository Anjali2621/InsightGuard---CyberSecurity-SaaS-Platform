from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os

from app.api import logs, incidents
from app.storage.database import engine
from app.models.model import Base

try:
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully")
except Exception as e:
    print(f"Error creating database tables: {e}")

app = FastAPI(title="InsightGuard Backend")

# Allow the dashboard (opened from file:// or localhost) to talk to the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "https://extraordinary-entremet-0f1664.netlify.app",  # Your Netlify URL
    "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router)
app.include_router(incidents.router)
print("Routers mounted successfully")


@app.get("/test")
def test_endpoint():
    return {"message": "API is working!", "routes": ["GET /", "GET /logs", "POST /logs/upload", "GET /dashboard"]}


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



