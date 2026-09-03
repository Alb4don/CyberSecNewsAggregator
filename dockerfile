FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system --gid 10001 news \
    && useradd --system --uid 10001 --gid news --home-dir /nonexistent --shell /usr/sbin/nologin news \
    && mkdir -p /data \
    && chown -R 10001:10001 /data

COPY --chown=10001:10001 requirements.txt cybersecnews.py ./

RUN pip install --no-cache-dir -r requirements.txt

USER 10001:10001

ENV HOST=0.0.0.0 \
    PORT=8000 \
    DB_PATH=/data/cybernews_data.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=8s --start-period=25s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=5).status == 200 else 1)"]

ENTRYPOINT ["python", "cybersecnews.py"]
