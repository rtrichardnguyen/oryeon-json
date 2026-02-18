# ---------- Stage 1: build zgrab2 ----------
FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux:2 AS build-zgrab2

RUN yum -y update && \
    yum -y install golang git make ca-certificates && \
    yum clean all

WORKDIR /src
COPY tools/zgrab2/ .

RUN go build -o /tmp/zgrab2 ./cmd/zgrab2/ && \
    chmod +x /tmp/zgrab2


# ---------- Stage 2: Lambda runtime ----------
FROM --platform=linux/amd64 public.ecr.aws/lambda/python:3.10

# Put zgrab2 on PATH
COPY --from=build-zgrab2 /tmp/zgrab2 /opt/bin/zgrab2
ENV PATH="/opt/bin:${PATH}"

# Copy app files
COPY app.py              ${LAMBDA_TASK_ROOT}/
COPY requirements.txt    ${LAMBDA_TASK_ROOT}/
COPY GeoLite2-ASN.mmdb  ${LAMBDA_TASK_ROOT}/
COPY GeoLite2-City.mmdb ${LAMBDA_TASK_ROOT}/
COPY encoders/           ${LAMBDA_TASK_ROOT}/encoders/

# Install Python dependencies
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt -t ${LAMBDA_TASK_ROOT}

CMD ["app.lambda_handler"]
