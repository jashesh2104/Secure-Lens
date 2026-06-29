"""RAG retrieval engine: ChromaDB persistent store + embeddings.

Embeddings are produced locally by Ollama (`nomic-embed-text`). If Ollama is
not reachable we fall back to ChromaDB's bundled ONNX model and flag it loudly,
rather than silently switching to a paid API. The same collection is shared by
the ingest script and the triage agent so they stay in sync.
"""

from __future__ import annotations

import chromadb
import requests
from chromadb.utils import embedding_functions

from app.config import get_settings

settings = get_settings()


def _ollama_available() -> bool:
    """Return True if a local Ollama server responds, else False."""
    try:
        resp = requests.get(f"{settings.ollama_base_url}/api/tags", timeout=2)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def get_embedding_function():
    """Pick Ollama embeddings; fall back to bundled ONNX with a clear warning."""
    if _ollama_available():
        return embedding_functions.OllamaEmbeddingFunction(
            url=f"{settings.ollama_base_url}/api/embeddings",
            model_name=settings.embedding_model,
        )
    print(
        "[rag_engine] WARNING: Ollama not reachable at "
        f"{settings.ollama_base_url}; falling back to ChromaDB's bundled ONNX "
        "model (all-MiniLM-L6-v2). Install Ollama + nomic-embed-text for the "
        "intended local embeddings."
    )
    return embedding_functions.DefaultEmbeddingFunction()


def get_collection() -> chromadb.Collection:
    """Open (or create) the persistent knowledge-base collection."""
    client = chromadb.PersistentClient(path=settings.chroma_dir)
    return client.get_or_create_collection(
        name=settings.chroma_collection,
        embedding_function=get_embedding_function(),
    )


def retrieve(query: str, k: int = 4) -> list[str]:
    """Return the top-k knowledge-base chunks most relevant to the query."""
    collection = get_collection()
    result = collection.query(query_texts=[query], n_results=k)
    docs = result.get("documents") or [[]]
    return docs[0]
