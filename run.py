#!/usr/bin/env python3
"""
Replit Startup Script for InsightGuard

This script runs the FastAPI application.
The actual app code is in app/main.py
"""
import uvicorn
from app.main import app

if __name__ == "__main__":
    print("🚀 Starting InsightGuard Backend...")
    print("📍 API will be available at: https://your-replit-url")
    print("📊 Frontend: https://your-replit-url/dashboard")
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )