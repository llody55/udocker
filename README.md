# udocker
docker面板管理
## 启动方式
```
docker run -itd --name uocker -p 8000:8000 -p 9002:9002 -v /var/run/docker.sock:/var/run/docker.sock  udocker:v1
```