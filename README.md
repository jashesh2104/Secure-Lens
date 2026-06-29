# SecureLens

Self-hosted, AI-augmented DevSecOps triage platform. SecureLens runs SonarQube
and Gitleaks against a target repo, normalizes findings into a unified schema,
then uses a Retrieval-Augmented Generation (RAG) pipeline grounded in an
OWASP Top 10 / CWE Top 25 knowledge base to re-rank severity and generate
plain-English explanations, exploit scenarios, and fix suggestions.

Existing scanners detect and list findings; SecureLens adds an explanation and
prioritization layer on top of detection.

## Stack
- Backend: FastAPI + synchronous SQLAlchemy (SQLite locally, Postgres on EC2)
- Scanners: SonarQube Community Build + Gitleaks
- LLM: Groq API · Embeddings: Ollama (`nomic-embed-text`) · Vector store: ChromaDB
- Frontend: React + Vite + Tailwind (added later)

## Status
Phase 1, Step 1: backend skeleton + `/health`. See [backend/README.md](backend/README.md).
