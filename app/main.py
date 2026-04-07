"""Audit Copilot — FastAPI entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_analyze import router as analyze_router
from app.api.routes_jobs import router as jobs_router
from app.api.routes_reports import router as reports_router
from app.config import settings

app = FastAPI(
    title="Audit Copilot",
    description="iPad-first smart contract audit assistant",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router, tags=["analyze"])
app.include_router(jobs_router, tags=["jobs"])
app.include_router(reports_router, tags=["reports"])


@app.get("/")
async def root():
    return {
        "name": "Audit Copilot",
        "version": "0.1.0",
        "status": "running",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.app_port)
