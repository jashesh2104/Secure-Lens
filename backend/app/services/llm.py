"""Central chat-model factory shared by triage and fix generation.

GitHub Models (the former GitHub-hosted inference API) was retired on
2026-07-30, and a backend service cannot reuse the editor's GitHub Copilot
session, so SecureLens talks to a standard OpenAI-compatible endpoint instead.
``LLM_PROVIDER`` selects the backend:

* ``openai`` — any OpenAI-compatible API: OpenAI, an **Azure AI Foundry** models
  endpoint, or a local server (Ollama/vLLM/LM Studio). This is the default and
  the recommended successor to GitHub Models.
* ``azure`` — a classic Azure OpenAI deployment (endpoint + deployment name).
* ``groq`` — the legacy provider, kept working as a fallback.

Both triage and fix import :func:`get_chat_model` so switching providers is a
single ``.env`` change with no code edits. Provider SDKs are imported lazily so
an unused provider never has to be installed.
"""

from __future__ import annotations

from app.config import get_settings

settings = get_settings()


def provider() -> str:
    """The configured provider name, normalized; defaults to ``openai``."""
    return (settings.llm_provider or "openai").strip().lower()


def llm_available() -> bool:
    """True when the selected provider has the credentials it needs to run."""
    p = provider()
    if p == "groq":
        return bool(settings.groq_api_key)
    if p == "azure":
        return bool(
            settings.azure_openai_api_key
            and settings.azure_openai_endpoint
            and settings.azure_openai_deployment
        )
    return bool(settings.openai_api_key)


def unavailable_reason() -> str:
    """A user-facing message explaining what to configure for the provider."""
    p = provider()
    if p == "groq":
        return "LLM disabled: GROQ_API_KEY is not set."
    if p == "azure":
        return (
            "LLM disabled: Azure OpenAI is not configured. Set "
            "AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT and "
            "AZURE_OPENAI_DEPLOYMENT (or switch LLM_PROVIDER)."
        )
    return (
        "LLM disabled: no OpenAI-compatible endpoint configured. Set "
        "OPENAI_API_KEY (and OPENAI_BASE_URL / OPENAI_MODEL for Azure AI "
        "Foundry or a local server), or switch LLM_PROVIDER=groq."
    )


def get_chat_model():
    """Return a temperature-0 chat model for the configured provider.

    Callers use ``.with_structured_output(...)`` on the result, which every
    supported provider implements, so the rest of the pipeline is unchanged.
    """
    p = provider()
    if p == "groq":
        from langchain_groq import ChatGroq

        return ChatGroq(
            model=settings.groq_model, temperature=0,
            api_key=settings.groq_api_key,
        )
    if p == "azure":
        from langchain_openai import AzureChatOpenAI

        return AzureChatOpenAI(
            azure_endpoint=settings.azure_openai_endpoint,
            api_key=settings.azure_openai_api_key,
            api_version=settings.azure_openai_api_version,
            azure_deployment=settings.azure_openai_deployment,
            temperature=0,
        )
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model=settings.openai_model, temperature=0,
        api_key=settings.openai_api_key, base_url=settings.openai_base_url,
    )
