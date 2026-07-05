# The official ZAP image already includes Java, ZAP, and zap-baseline.py on PATH,
# plus a Python 3 runtime. We layer our small consumer on top.
FROM ghcr.io/zaproxy/zaproxy:stable

# ZAP runs as the non-root "zap" user; switch to root just to install our deps.
USER root
WORKDIR /app

# The ZAP image's python is externally managed (PEP 668); --break-system-packages
# lets us add our few libs into it.
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY app/ ./app/

# /zap/wrk is ZAP's conventional writable working dir for reports. Make sure it exists
# and is writable by whoever runs the scan.
RUN mkdir -p /zap/wrk && chmod 777 /zap/wrk

# Fail the build if the ZAP baseline script isn't where we expect it.
RUN which zap-baseline.py

# Drop back to ZAP's built-in non-root user for runtime — we only needed root to install deps.
# /zap/wrk is chmod 777 above so zap can still write reports; uvicorn binds 8007 (>1024, no root
# needed). Satisfies CKV_DOCKER_8 (last USER must not be root) with a real fix, not a skip.
USER zap

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8007"]