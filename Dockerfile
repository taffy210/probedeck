FROM python:3.12-slim

# Diagnostic toolset. iputils for ping, dnsutils for dig/nslookup,
# iperf3 for throughput, nmap for discovery, tcpdump for capture,
# mtr-tiny for the json-capable mtr, plus curl/whois/traceroute.
RUN apt-get update && apt-get install -y --no-install-recommends \
        mtr-tiny \
        iputils-ping \
        traceroute \
        dnsutils \
        iperf3 \
        nmap \
        tcpdump \
        whois \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

ENV PROBEDECK_DATA=/data
EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
