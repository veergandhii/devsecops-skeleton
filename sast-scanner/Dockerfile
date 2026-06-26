FROM python:3.12-slim

WORKDIR /app

# Semgrep needs git to resolve rules from the registry
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Patch pip-tooling CVEs (wheel + setuptools/jaraco.context) baked into the base image.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
# Semgrep needs our bundled rules at runtime. scanner.py resolves them to
# /app/rules/python-security.yml — so they must be copied into the image.
COPY rules/ ./rules/

# Fail the build if either SAST tool isn't on PATH — catches a bad install at build time.
RUN semgrep --version && bandit --version

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
