FROM cgr.dev/chainguard/python:latest-dev@sha256:9944f77e5734846d1cfa02aee577482ef6ef019e6ec6d0b1cfebab4ebba19be6 AS build

USER root
RUN apk update && apk add --no-cache git openssh ca-certificates-bundle

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt certbot==5.6.0

COPY app/ ./app/
COPY scripts/ ./scripts/
COPY config.yaml .
COPY --chmod=+x scripts/deploy-hook.sh /opt/deploy-hook.sh

RUN mkdir -p /data/acme-git-webhook/letsencrypt && \
    addgroup --system app && adduser --system --ingroup app app && \
    chown -R app:app /app /data

FROM cgr.dev/chainguard/python:latest@sha256:bbae4504f6381ba41b65111ce3bb229a7c4f4def6ac400576705044414a09001

WORKDIR /app

COPY --from=build /app /app
COPY --from=build /opt/deploy-hook.sh /opt/deploy-hook.sh
COPY --from=build /data /data

COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /etc/ssh /etc/ssh
RUN ["rm", "-f", "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ecdsa_key"]

COPY --from=build /usr/bin/git /usr/bin/git
COPY --from=build /usr/libexec/git-core /usr/libexec/git-core
COPY --from=build /usr/bin/ssh /usr/bin/ssh
COPY --from=build /usr/bin/ssh-keygen /usr/bin/ssh-keygen
COPY --from=build /usr/lib/ssh /usr/lib/ssh

COPY --from=build /usr/lib/python3.14/site-packages /usr/lib/python3.14/site-packages/
COPY --from=build /usr/bin/uvicorn /usr/bin/uvicorn
COPY --from=build /usr/bin/certbot /usr/bin/certbot

USER app
EXPOSE 8000
ENTRYPOINT []
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
