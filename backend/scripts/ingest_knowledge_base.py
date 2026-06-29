"""One-off ingest: chunk the OWASP/CWE knowledge base and store in ChromaDB.

Run from the backend dir:
    .\.venv\Scripts\python.exe -m scripts.ingest_knowledge_base

Idempotent: clears the collection first so re-running gives a clean rebuild.
Chunks are kept small (~800 chars) so retrieval returns focused, relevant
passages instead of whole files; overlap preserves context across boundaries.
"""

from __future__ import annotations

import glob
import os

from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.config import get_settings
from app.services.rag_engine import get_collection

settings = get_settings()


def main() -> None:
    files = sorted(glob.glob(os.path.join(settings.knowledge_base_dir, "*.md")))
    if not files:
        raise SystemExit(f"No .md files in {settings.knowledge_base_dir}")

    splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=120)
    collection = get_collection()

    # Clean rebuild: drop any existing docs in the collection.
    existing = collection.get().get("ids", [])
    if existing:
        collection.delete(ids=existing)

    ids, docs, metadatas = [], [], []
    for path in files:
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for i, chunk in enumerate(splitter.split_text(text)):
            ids.append(f"{name}::{i}")
            docs.append(chunk)
            metadatas.append({"source": name})

    collection.add(ids=ids, documents=docs, metadatas=metadatas)
    print(f"Ingested {len(docs)} chunks from {len(files)} docs into "
          f"'{settings.chroma_collection}' at {settings.chroma_dir}")


if __name__ == "__main__":
    main()
