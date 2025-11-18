from functools import lru_cache

from langchain_openai.chat_models import ChatOpenAI

from app.config.settings import get_llm_settings

llm_settings = get_llm_settings()


@lru_cache(maxsize=20)
def _get_model():
    return ChatOpenAI(
        base_url=llm_settings.OPENAI_BASE_URL,
        model=llm_settings.OPENAI_MODEL_NAME,
        api_key=llm_settings.OPENAI_API_KEY,
        timeout=60,
        max_retries=2,
    )
