import os

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import get_settings
from app.config.security import validate_api_key
from app.routers.analyzer import analyzer_router
 
# Create the FastAPI app
app = FastAPI(
    title="Analyzer",
    description="API for AI Analyzer",
    dependencies=[Depends(validate_api_key)],
    version="0.1.0",
)
os.environ["TOKENIZERS_PARALLELISM"] = "false"
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=settings.CORS_METHODS,
    allow_headers=settings.CORS_HEADERS,
    allow_credentials=settings.CORS_CREDENTIALS,
)

app.include_router(analyzer_router, prefix="/v1")


@app.get("/")
async def root():
    return {"message": "Welcome to Voice API!!!"}
