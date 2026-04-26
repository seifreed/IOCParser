FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY iocparser /app/iocparser

RUN python -m pip install --upgrade pip && \
    pip install .

ENTRYPOINT ["iocparser-worker"]
