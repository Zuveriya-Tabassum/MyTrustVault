FROM python:3.12-slim
WORKDIR /srv
ENV PYTHONUNBUFFERED=1 STORAGE_DIR=/tmp/storage COOKIE_SECURE=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -r tv && mkdir -p /tmp/storage && chown tv /tmp/storage
USER tv
EXPOSE 8000
# seed = create tables/triggers + demo users/documents (idempotent), then serve
CMD ["sh","-c","python -m app.seed && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
