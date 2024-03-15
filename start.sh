#!/bin/bash
# start.sh

# 启动udocker程序，并让其在后台运行
./bin/udocker &

# 启动Django程序
python3 manage.py runserver 0.0.0.0:9002
