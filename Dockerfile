# ---------- Stage 1: build zgrab2 on Amazon Linux 2 ----------
FROM public.ecr.aws/amazonlinux/amazonlinux:2 AS build-zgrab2

RUN yum -y update && \
    yum -y install golang git make ca-certificates && \
    yum clean all

WORKDIR /src
COPY . .

# Build zgrab2 (try make first; fallback to go build)
WORKDIR /src/tools/zgrab2
RUN (make zgrab2 && cp zgrab2 /tmp/zgrab2) || \
    (go build -o /tmp/zgrab2 ./... )

RUN chmod +x /tmp/zgrab2


# ---------- Stage 2: Lambda runtime ----------
FROM public.ecr.aws/lambda/python:3.11

# Put zgrab2 on PATH
COPY --from=build-zgrab2 /tmp/zgrab2 /opt/bin/zgrab2
ENV PATH="/opt/bin:${PATH}"

# Copy your app + data files into the Lambda task root
# (This includes your GeoLite2 mmdb files)
COPY app.py ${LAMBDA_TASK_ROOT}/app.py
COPY requirements.txt ${LAMBDA_TASK_ROOT}/requirements.txt
COPY GeoLite2-ASN.mmdb ${LAMBDA_TASK_ROOT}/GeoLite2-ASN.mmdb
COPY GeoLite2-City.mmdb ${LAMBDA_TASK_ROOT}/GeoLite2-City.mmdb
COPY encoders/ ${LAMBDA_TASK_ROOT}/encoders/

# Install python deps if you have any
RUN pip install -r ${LAMBDA_TASK_ROOT}/requirements.txt -t ${LAMBDA_TASK_ROOT} || true

# Handler
CMD ["app.lambda_handler"]

