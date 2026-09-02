from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="AI-Powered Security & Quantum Readiness Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.get("/")
async def root():
    return {"service": settings.app_name, "status": "operational", "docs": "/docs"}


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.environment,
        "version": "0.2.0",
        "scanners": {
            "crypto_scanner": "operational",
            "cert_scanner": "operational",
            "dependency_scanner": "operational",
            "container_scanner": "operational",
            "binary_scanner": "operational",
            "hsm_cloud_scanner": "operational",
        }
    }
