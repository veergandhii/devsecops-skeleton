# webhook-receiver

Simple FastAPI service that receives webhooks and exposes basic health info.

## Local Run

Install dependencies:

pip install -r requirements.txt

Start the server:

d:/devsecops/devsecops-skeleton/.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000 --env-file .env

## Docker Run

Build the image:

docker build -t webhook-receiver:0.1.0 .

Run the container:

docker run --rm -p 8000:8000 --name webhook-receiver webhook-receiver:0.1.0

## Endpoints

- GET /
- GET /health
- POST /webhook
