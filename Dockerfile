# 第一阶段
FROM --platform=$TARGETPLATFORM python:3.9.10-slim as builder
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETARCH

ENV PIP_CACHE_DIR=/app/.cache \
    LANG=en_GB.UTF-8 \
    DOCKER_HOST=unix:///var/run/docker.sock

RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .

# 安装平台特定的依赖
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
      pip install --no-cache-dir pysqlite3-binary==0.5.2.post3; \
    fi

RUN pip install --no-cache-dir -r requirements.txt && python -m pip install Pillow 

# 第二阶段
FROM --platform=$TARGETPLATFORM python:3.9.10-slim
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETARCH

MAINTAINER llody55

COPY --from=builder /usr/local/lib/python3.9 /usr/local/lib/python3.9

WORKDIR /app

COPY . /app

RUN chmod +x start.sh

EXPOSE 9002
EXPOSE 8000

CMD ["./start.sh"]
