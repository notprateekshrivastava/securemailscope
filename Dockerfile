FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY README.md FRONTEND_API.md ./
RUN mkdir -p /app/data/uploads /app/data/analyses /app/models

EXPOSE 8000
CMD ["sh", "-c", "python -m app.ml.train && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
