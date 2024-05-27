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
#RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/ && python -m pip install Pillow -i https://mirrors.aliyun.com/pypi/simple/
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

# 初始化数据库
RUN python manage.py migrate
RUN echo "from django.contrib.auth.models import apps; apps.objects.create_superuser('llody', '745719408@qq.com', '1qaz2wsx')" | python manage.py shell

RUN chmod +x start.sh

EXPOSE 9002
EXPOSE 8000

CMD ["./start.sh"]