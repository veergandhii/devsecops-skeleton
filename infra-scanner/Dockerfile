FROM python:3.12-slim

WORKDIR /app

# System deps for adding Trivy's apt repo.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg ca-certificates apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy from its official apt repository.
# Import Aqua's signing key, register the repo, then apt-install. Using the repo
# (vs a raw binary download) means `apt-get upgrade` keeps Trivy patched too.
# Install Trivy from its official apt repository.
RUN curl -fsSL https://get.trivy.dev/deb/public.key \
      | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://get.trivy.dev/deb generic main" \
      > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*
    
# Install Checkov. It is a Python tool.
# On Python 3.12 the base image's pip guards the system env; --break-system-packages
# lets us install into it anyway (fine inside a single-purpose container).
RUN pip install --no-cache-dir checkov --break-system-packages

# App deps and code.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/

# Fail the build if either tool is missing.
RUN trivy --version && checkov --version

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8004"]
