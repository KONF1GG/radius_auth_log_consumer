FROM python:3.13-alpine

RUN apk add --no-cache \
    build-base \
    python3-dev \
    libffi-dev \
    gcc \
    musl-dev \
    libressl-dev  # Changed from libssl-dev to libressl-dev

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ADD . /app

WORKDIR /app

RUN uv venv

ENV UV_PROJECT_ENVIRONMENT=/env

RUN uv sync --frozen --no-cache

CMD ["uv", "run", "main.py"]
