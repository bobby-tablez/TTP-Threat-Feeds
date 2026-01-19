"""
LLM Provider abstraction layer for TTP-Threat-Feeds
Supports multiple LLM backends: LM Studio, Ollama, OpenAI, Claude, Gemini
"""

import os
import json
import requests
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any


class LLMProvider(ABC):
    """Base class for LLM providers"""

    def __init__(self, model_name: Optional[str] = None, **kwargs):
        self.model_name = model_name
        self.config = kwargs

    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 5000) -> str:
        """
        Generate a response from the LLM

        Args:
            system_prompt: System message/context
            user_prompt: User message/query
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text response
        """
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the name of this provider"""
        pass


class LMStudioProvider(LLMProvider):
    """LM Studio local LLM provider (OpenAI-compatible endpoint)"""

    def __init__(self, endpoint: str = "http://127.0.0.1:1234/v1/chat/completions",
                 model_name: str = "qwen2.5-coder-32b-instruct", **kwargs):
        super().__init__(model_name, **kwargs)
        self.endpoint = endpoint
        self.headers = {"Content-Type": "application/json"}

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 5000) -> str:
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        try:
            resp = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()

            if "choices" not in data:
                raise ValueError(f"Unexpected LLM response: {data}")

            return data["choices"][0]["message"]["content"]
        except Exception as e:
            raise RuntimeError(f"LM Studio API request failed: {e}")

    def get_provider_name(self) -> str:
        return "LM Studio"


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider"""

    def __init__(self, endpoint: str = "http://127.0.0.1:11434/api/chat",
                 model_name: str = "qwen2.5-coder:32b", **kwargs):
        super().__init__(model_name, **kwargs)
        self.endpoint = endpoint
        self.headers = {"Content-Type": "application/json"}

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 5000) -> str:
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }

        try:
            resp = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()

            if "message" not in data:
                raise ValueError(f"Unexpected Ollama response: {data}")

            return data["message"]["content"]
        except Exception as e:
            raise RuntimeError(f"Ollama API request failed: {e}")

    def get_provider_name(self) -> str:
        return "Ollama"


class OpenAIProvider(LLMProvider):
    """OpenAI API provider"""

    def __init__(self, api_key: Optional[str] = None,
                 model_name: str = "gpt-4o", **kwargs):
        super().__init__(model_name, **kwargs)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not provided. Set OPENAI_API_KEY environment variable or pass api_key parameter")

        self.endpoint = "https://api.openai.com/v1/chat/completions"
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 5000) -> str:
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        try:
            resp = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=120)

            # If error, try to get the error message
            if resp.status_code != 200:
                try:
                    error_data = resp.json()
                    error_msg = error_data.get('error', {}).get('message', resp.text)
                    raise ValueError(f"OpenAI API error ({resp.status_code}): {error_msg}")
                except (ValueError, KeyError):
                    resp.raise_for_status()

            data = resp.json()

            if "choices" not in data:
                raise ValueError(f"Unexpected OpenAI response: {data}")

            return data["choices"][0]["message"]["content"]
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"OpenAI API request failed: {e}")
        except Exception as e:
            raise RuntimeError(f"OpenAI API error: {e}")

    def get_provider_name(self) -> str:
        return "OpenAI"


class ClaudeProvider(LLMProvider):
    """Anthropic Claude API provider"""

    def __init__(self, api_key: Optional[str] = None,
                 model_name: str = "claude-3-5-sonnet-20241022", **kwargs):
        super().__init__(model_name, **kwargs)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Anthropic API key not provided. Set ANTHROPIC_API_KEY environment variable or pass api_key parameter")

        self.endpoint = "https://api.anthropic.com/v1/messages"
        self.headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 5000) -> str:
        # Validate inputs
        if not isinstance(system_prompt, str):
            raise ValueError(f"system_prompt must be a string, got {type(system_prompt)}")
        if not isinstance(user_prompt, str):
            raise ValueError(f"user_prompt must be a string, got {type(user_prompt)}")

        payload = {
            "model": self.model_name,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        try:
            resp = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=120)

            # If error, try to get the error message from Claude's response
            if resp.status_code != 200:
                try:
                    error_data = resp.json()
                    error_msg = error_data.get('error', {}).get('message', resp.text)
                    raise ValueError(f"Claude API error ({resp.status_code}): {error_msg}")
                except (ValueError, KeyError):
                    resp.raise_for_status()

            data = resp.json()

            if "content" not in data:
                raise ValueError(f"Unexpected Claude response: {data}")

            # Claude returns content as a list of content blocks
            return data["content"][0]["text"]
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Claude API request failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Claude API error: {e}")

    def get_provider_name(self) -> str:
        return "Claude"


class GeminiProvider(LLMProvider):
    """Google Gemini API provider"""

    def __init__(self, api_key: Optional[str] = None,
                 model_name: str = "gemini-2.0-flash-exp", **kwargs):
        super().__init__(model_name, **kwargs)
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("Google API key not provided. Set GOOGLE_API_KEY environment variable or pass api_key parameter")

        self.model_name = model_name
        self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={self.api_key}"
        self.headers = {"Content-Type": "application/json"}
        self.last_request_time = 0  # Track last request for rate limiting
        self.min_request_interval = 4.5  # Minimum seconds between requests (15 RPM = 4s, add buffer)

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 5000) -> str:
        import time

        # Rate limiting for free tier (15 requests/minute)
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_request_interval:
            wait_time = self.min_request_interval - time_since_last
            print(f"    ⏱️  Gemini rate limit: waiting {wait_time:.1f}s...")
            time.sleep(wait_time)

        self.last_request_time = time.time()

        # Gemini combines system and user prompts differently
        combined_prompt = f"{system_prompt}\n\n{user_prompt}"

        payload = {
            "contents": [{
                "parts": [{"text": combined_prompt}]
            }],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            }
        }

        try:
            resp = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=120)

            # Better error handling for Gemini
            if resp.status_code == 429:
                raise RuntimeError("Gemini rate limit exceeded. Free tier allows 15 requests/minute. Try again in a minute or upgrade your plan.")
            elif resp.status_code != 200:
                try:
                    error_data = resp.json()
                    error_msg = error_data.get('error', {}).get('message', resp.text)
                    raise ValueError(f"Gemini API error ({resp.status_code}): {error_msg}")
                except (ValueError, KeyError):
                    resp.raise_for_status()

            data = resp.json()

            if "candidates" not in data or len(data["candidates"]) == 0:
                raise ValueError(f"Unexpected Gemini response: {data}")

            return data["candidates"][0]["content"]["parts"][0]["text"]
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Gemini API request failed: {e}")
        except Exception as e:
            raise RuntimeError(f"Gemini API error: {e}")

    def get_provider_name(self) -> str:
        return "Gemini"


def create_provider(provider_type: str, **kwargs) -> LLMProvider:
    """
    Factory function to create LLM providers

    Args:
        provider_type: One of 'lmstudio', 'ollama', 'openai', 'claude', 'gemini'
        **kwargs: Provider-specific configuration

    Returns:
        LLMProvider instance
    """
    providers = {
        'lmstudio': LMStudioProvider,
        'ollama': OllamaProvider,
        'openai': OpenAIProvider,
        'claude': ClaudeProvider,
        'gemini': GeminiProvider
    }

    provider_type = provider_type.lower()
    if provider_type not in providers:
        raise ValueError(f"Unknown provider type: {provider_type}. Available: {', '.join(providers.keys())}")

    return providers[provider_type](**kwargs)
