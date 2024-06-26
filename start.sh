#!/bin/bash
# start.sh

ARCH=$(uname -m)

# 启动udocker程序，并让其在后台运行
if [ "$ARCH" = "x86_64" ]; then
  chmod +x ./bin/amd64/udocker
  ./bin/amd64/udocker &
elif [ "$ARCH" = "aarch64" ]; then
  chmod +x ./bin/arm64/udocker
  ./bin/arm64/udocker &
else
  echo "Unsupported architecture"
  exit 1
fi

# 启动Django程序
python3 manage.py runserver 0.0.0.0:9002
