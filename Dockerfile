FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

COPY . .

CMD gunicorn "api.api:app" \
    --bind "${SERVER_HOST:-0.0.0.0}:${SERVER_PORT:-5000}" \
    ${SERVER_INTERNAL_HOST:+--bind "${SERVER_INTERNAL_HOST}:${SERVER_PORT:-5000}"} \
    --workers 1 --worker-class gthread --threads 32 \
    --timeout 300 --access-logfile -
