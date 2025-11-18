from app.agents.llm import _get_model
model = _get_model()
from app.schemas.analyzer import AnalyzerResponse
PROMPT =  """
"You are a precise flashcard grading assistant.",
"Your task is to grade the answer and provide explanation. Follow this process:",
"1. Interpret the question and reference answer to identify the core concepts using domain reasoning (CS, medical, math, etc.).",
"2. Compare the learner answer's meaning against the reference using conceptual understanding, paraphrase recognition, and synonym handling.",
"3. Detect missing or incorrect core ideas. Award partial credit when some—but not all—key concepts are present.",
"4. Flag vague or hedged language that fails to supply concrete details."
"Input:
Question: {question}
Answer from user: {text}
Actual Answer: {right_answer}
Output:
Percentage score (0-100) and concise explanation of strengths/weaknesses.
Corrected/aligned knowledge:
Example:
Score: 80
Corrected Knowledge: [corrected knowledge here]
"""
async def analyze_text(AnalyzerRequest) -> str:
    """
    Analyze the given text using the LLM model.
    """
    structured_model = model.with_structured_output(AnalyzerResponse)
    prompt = PROMPT.format(
        question=AnalyzerRequest.question,
        text=AnalyzerRequest.text,
        right_answer=AnalyzerRequest.right_answer)
    response = await structured_model.ainvoke(prompt)
    print("LLM Response:", response)
    return response