from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

class AnalyzerRequest(BaseModel):
    question: str = Field(..., description="Question to analyze")
    text: str = Field(..., description="Text to analyze")
    right_answer: Optional[str] = Field(None, description="The correct answer for comparison")

class AnalyzerResponse(BaseModel):
    message: str = Field(..., description="Analysis result message")