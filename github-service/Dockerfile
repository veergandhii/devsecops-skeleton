FROM python:3.12-slim
WORKDIR /app
# Patch pip-tooling CVEs (wheel + setuptools/jaraco.context) baked into the base image.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8006"]
