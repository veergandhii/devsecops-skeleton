FROM python:3.12-slim

WORKDIR /app

# Install git — Semgrep needs it to resolve rules from the registry
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Confirm both SAST tools are actually on PATH at build time — fast fail if not
RUN semgrep --version && bandit --version

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]