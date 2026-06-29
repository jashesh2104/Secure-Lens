# Backend image. Deployment-only (no Docker locally). On EC2 we add psycopg
# for Postgres; sonar-scanner/gitleaks are installed in the runner/CI, not here.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt psycopg2-binary

COPY . .
EXPOSE 8000
# Run migrations then start the API.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
