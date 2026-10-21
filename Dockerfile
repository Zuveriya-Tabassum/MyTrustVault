FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -r tv && mkdir -p /srv/storage && chown tv /srv/storage
USER tv
CMD ["sh","-c","python -m app.seed && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
