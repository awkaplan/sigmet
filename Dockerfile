FROM python:2.7.13-alpine
MAINTAINER Alex Kaplan <github.com/awkaplan>

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev
RUN pip install requests f5-sdk PyJWT cryptography
COPY sigmet.py .

ENTRYPOINT ["python", "sigmet.py"]
