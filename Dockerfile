FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client certbot \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/deploy-hook.sh /opt/deploy-hook.sh
RUN chmod +x /opt/deploy-hook.sh

RUN addgroup --system app && adduser --system --ingroup app app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY scripts/ ./scripts/
COPY config.yaml .

RUN mkdir -p /data/acme-git-webhook/letsencrypt && chown -R app:app /data/acme-git-webhook

USER app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
