FROM python:3.12-slim
WORKDIR /app
# Patch pip-tooling CVEs (wheel + setuptools/jaraco.context) baked into the base image.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001", "--loop", "asyncio", "--http", "h11"]