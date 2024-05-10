#!/bin/bash
# start.sh

ARCH=$(uname -m)

# 启动udocker程序，并让其在后台运行
if [ "$ARCH" = "x86_64" ]; then
  ./bin/amd64/udocker &
elif [ "$ARCH" = "aarch64" ]; then
  ./bin/arm64/udocker &
else
  echo "Unsupported architecture"
  exit 1
fi

# 启动Django程序
python3 manage.py runserver 0.0.0.0:9002
