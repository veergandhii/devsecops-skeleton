FROM python:3.12-slim

WORKDIR /app

# curl: download the tool tarballs.
# git : Gitleaks can use git internally; harmless to have even in --no-git mode.
# ca-certificates: lets curl validate the GitHub TLS cert when downloading.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Gitleaks publishes prebuilt binaries on GitHub Releases. Asset name: gitleaks_<ver>_linux_x64.tar.gz
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
      | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# TruffleHog asset uses linux_amd64 in its name (different naming convention from Gitleaks).
RUN curl -sSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.6/trufflehog_3.95.6_linux_amd64.tar.gz \
      | tar -xz -C /usr/local/bin trufflehog \
    && chmod +x /usr/local/bin/trufflehog

# Patch pip-tooling CVEs (wheel + setuptools/jaraco.context) baked into the base image.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Fail the build if either tool isn't on PATH — catches a bad download URL at build time.
RUN gitleaks version && trufflehog --version

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
