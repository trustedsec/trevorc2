FROM alpine:edge


RUN apk --update add --no-cache python3 py3-requests py3-pip openssl ca-certificates
RUN apk --update add --virtual build-dependencies python3-dev build-base wget git \
  && git clone https://github.com/trustedsec/trevorc2.git
WORKDIR trevorc2

#COPY requirements.txt .
RUN pip3 install -r requirements.txt
EXPOSE 80 443
ENTRYPOINT ["python3", "trevorc2_server.py"]