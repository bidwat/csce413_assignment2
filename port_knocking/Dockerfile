FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iptables iproute2 openssh-server netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY knock_server.py knock_client.py entrypoint.sh ./

RUN chmod +x /app/entrypoint.sh

EXPOSE 1234 5678 9012 2222

CMD ["/app/entrypoint.sh"]
