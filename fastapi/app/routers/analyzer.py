import base64
import os
from uuid import UUID

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import Response, StreamingResponse
from loguru import logger

from app.schemas.analyzer import AnalyzerRequest, AnalyzerResponse
from app.service.analyzer import analyze_text


analyzer_router = APIRouter(prefix="/analyzer", tags=["analyzer"])
@analyzer_router.get("/")
async def analyzer_hello():

    result = {"message": "Hello from Analyzer API!"}
    return result

@analyzer_router.post("/analyze", response_model=AnalyzerResponse)
async def analyze_endpoint(request: AnalyzerRequest):
    """
    Endpoint to analyze text using the LLM model.
    """
    try:
        analysis_result = await analyze_text(request)
        return AnalyzerResponse(message=analysis_result.content)
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")    
    