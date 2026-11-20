"""OpenAI-compatible LLM Provider Adapter.

Connects to any OpenAI-compatible inference endpoint (OpenAI, OpenRouter, DeepSeek,
Groq, Ollama, vLLM, LMStudio) using OPENAI_BASE_URL and OPENAI_API_KEY from .env.
Falls back safely to local mock / deterministic reasoning when no API key is set.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Type, TypeVar

from pydantic import BaseModel

from backend.config import get_settings

logger = logging.getLogger("llm_provider")
T = TypeVar("T", bound=BaseModel)


class OpenAICompatibleProvider:
    """Wrapper for OpenAI-compatible LLM endpoints."""

    def __init__(self):
        self.settings = get_settings()
        self._client: Optional[Any] = None
        self._chat_model: Optional[Any] = None

    @property
    def is_configured(self) -> bool:
        """Return True if an API key is provided and not a placeholder."""
        key = self.settings.get_effective_api_key()
        return bool(key and key != "your_api_key_here")

    def _get_chat_model(self):
        """Lazy-initialize ChatOpenAI client from langchain_openai."""
        if self._chat_model is None:
            if not self.is_configured:
                return None
            try:
                from langchain_openai import ChatOpenAI
                self._chat_model = ChatOpenAI(
                    model=self.settings.llm_model,
                    api_key=self.settings.get_effective_api_key(),
                    base_url=self.settings.openai_base_url,
                    temperature=0.1,
                    max_retries=2,
                    timeout=30.0,
                )
            except Exception as e:
                logger.error(f"Failed to initialize ChatOpenAI: {e}")
                return None
        return self._chat_model

    def structured_completion(
        self,
        prompt: str,
        schema: Type[T],
        system_instruction: str = "You are an autonomous expert Tier-3 SOC Analyst. Follow strict structured outputs.",
    ) -> Optional[T]:
        """Invoke LLM with strict structured Pydantic output."""
        model = self._get_chat_model()
        if model is None:
            return None

        try:
            structured_llm = model.with_structured_output(schema)
            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ]
            response = structured_llm.invoke(messages)
            return response
        except Exception as e:
            logger.warning(f"LLM structured completion failed: {e}. Falling back to rule/system1 baseline.")
            return None


llm_provider = OpenAICompatibleProvider()
