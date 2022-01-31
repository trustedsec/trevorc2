FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    openssl \
    ca-certificates \
    python3-dev \
    build-essential \
    wget \
    git \
    && \
    rm -fr /var/lib/apt/lists/*

RUN git clone https://github.com/trustedsec/trevorc2.git

WORKDIR trevorc2

COPY requirements.txt .

RUN pip3 install -r requirements.txt

EXPOSE 80 443
CMD ["python3", "trevorc2_server.py"]
