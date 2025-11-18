from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config.settings import get_settings

# Security scheme
Security = Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer())]

settings = get_settings()

# API Key validation
def validate_api_key(credentials: Security):
    """Validate API key from Authorization header."""
    expected_api_key = settings.API_KEY

    if credentials.credentials != expected_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials

