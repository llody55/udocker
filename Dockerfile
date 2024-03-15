FROM python:3.9.10

MAINTAINER llody55

ENV PIP_CACHE_DIR /app/.cache

ENV LANG en_GB.UTF-8

ENV DOCKER_HOST=unix:///var/run/docker.sock

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/ && \
    python -m pip install Pillow -i https://mirrors.aliyun.com/pypi/simple/

RUN chmod +x start.sh
EXPOSE 9002
EXPOSE 8000

CMD ["./start.sh"]