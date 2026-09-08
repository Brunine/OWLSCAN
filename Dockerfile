# OwlScan container image — ships nmap + masscan so the host system
# never needs either binary installed. Run with --cap-add=NET_RAW (and
# --cap-add=NET_ADMIN for masscan's raw-socket transmit path).
FROM nmap/nmap:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
        masscan \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN pip3 install --no-cache-dir --break-system-packages .[excel]

ENTRYPOINT ["owlscan"]
CMD ["--help"]