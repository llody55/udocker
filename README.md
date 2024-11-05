# udocker
<p align="center"><a href="#"><img src="https://static.llody.top/images/DM_20240323220512_001.png" alt="Image"></a></p>

**一个更简洁的Docker面板**

<div align="center">
<a href="https://github.com/llody55/udocker" target="_blank"><img alt="Github stars" src="https://img.shields.io/github/stars/llody55/udocker.svg" title="给个start吧，求求了"></a>
<img src="https://img.shields.io/badge/docker-123456?logo=docker&logoColor=fff&labelColor=1c7aed" alt="docker-udocker" style="display:inline-block;margin:0.2em;">
<img src="https://img.shields.io/github/v/release/llody55/udocker?label=latest&labelColor=107fbc" alt="udocker version" style="max-width: 100%;">
<img id="wechatIcon" alt="微信公众号" src="https://img.shields.io/badge/%E5%BE%AE%E4%BF%A1%E5%85%AC%E4%BC%97%E5%8F%B7-%E8%BF%90%E7%BB%B4%E5%AE%9E%E8%B7%B5%E5%BD%95-brightgreen"style="max-width: 100%;" title="给个关注吧，求求了">
</div>

> **声明:** 此项目当前为base版，请勿暴露于公网环境，可能引发安全问题
**如果此项目对你有用，请给一个**:star:

## 资源
> 1核1G即可轻松运行，支持只有 **X86** 和**arm64**架构

## 快速了解
> udocker 是一个轻量且好用的docker管理面板，并且自带一个webssh终端管理工具,可以很方便的管理服务器和上传下载文件。

目前支持的功能有：

   - 镜像管理
   - 容器管理
   - * 镜像回滚：可以对容器正在使用的镜像进行回滚版本，建议使用 **latest** 版本号时使用。
   - 网络管理
   - 存储管理
   - 事件中心
   - 镜像仓库管理（自带一个dockerhub的代理：docker.llody.cn）
   - 多语言(中英切换)
   - webssh终端
   - Linux文件管理器

## 安装与部署(推荐)
### 一键部署版
```bash
docker run --privileged -itd --name udocker -p 8000:8000 -p 9002:9002 -v /var/run/docker.sock:/var/run/docker.sock  docker.llody.cn/llody/udocker:latest
```
### 数据库持久化版
```bash
mkdir /opt/udocke_db
docker run --privileged -itd --name udocker -p 8000:8000 -p 9002:9002 -v /var/run/docker.sock:/var/run/docker.sock -v /opt/udocke_db:/app/db  docker.llody.cn/llody/udocker:latest
```
### 华为云同步镜像(国内推荐)
```bash
mkdir /opt/udocke_db
docker run --privileged -itd --name udocker -p 8000:8000 -p 9002:9002 -v /var/run/docker.sock:/var/run/docker.sock -v /opt/udocke_db:/app/db  swr.cn-southwest-2.myhuaweicloud.com/llody/udocker:latest 
```
### docker-compose方式(推荐)
```yaml
version: '3'

services:
  udocker:
    image: swr.cn-southwest-2.myhuaweicloud.com/llody/udocker:latest
    container_name: udocker
    privileged: true
    ports:
      - "8000:8000"
      - "9002:9002"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /opt/udocke_db:/app/db
    restart: always
```
> 启动方式：docker-compose up -d <br>
> 更新方式：docker-compose pull && docker-compose up -d --remove-orphans

### 账户密码

> 默认账户：llody 密码：1qaz2wsx

## 预览
### 系统信息
![1](./docs/images/1.png)
### 镜像管理
![2](./docs/images/2.png)
### 容器管理
![3](./docs/images/3.jpg)
### 网络管理
![4](./docs/images/4.jpg)
### 存储管理
![5](./docs/images/5.jpg)
### 事件中心
![6](./docs/images/6.jpg)
### 镜像仓库管理
![7](./docs/images/7.jpg)
### 创建容
![8](./docs/images/8.png)
### 创建网络
![9](./docs/images/9.jpg)
### 创建挂载信息
![10](./docs/images/10.jpg)
### 主机终端管理
![11](./docs/images/11.png)
### Linux文件管理器
![12](./docs/images/12.jpg)
### 文件批量上传
![13](./docs/images/13.jpg)


## HTTPS代理示例
### 七层反向代理
```nginx
server {
    listen      443 ssl;
    server_name udocker.llody.top;
    client_max_body_size 1000m;
    ssl_certificate /etc/nginx/llody.top/udocker.pem;
    ssl_certificate_key /etc/nginx/llody.top/udocker.key;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
    ssl_prefer_server_ciphers on;
    

    location / {
        proxy_pass http://192.168.1.236:9002/;
        proxy_set_header Host $http_host;
        proxy_set_header  X-Real-IP    $remote_addr;
        proxy_set_header  X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    location /apps/webssh_terminal/ {
        proxy_pass http://192.168.1.236:9002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    location /apps/docker_logs/ {
        proxy_pass http://192.168.1.236:9002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

  location /healthz {
    return 200;
  }
}
```
> 主要用于udocker面板的wss和https代理
### 四层反向代理
```nginx
server {
  listen 8000;
  proxy_pass 192.168.1.236:8000;
}
```
> 此代理主要是docker容器终端接口，存在**风险** ，暂时只实现连接，非必要可不做代理。

## 问题反馈
 - Issues

## 后续计划
  - docker-compose （支持）
  - 镜像拉取（优化）
  - 翻译（完善）
  - 优化BUG
  - 还想要什么，欢迎补充。

## Star趋势
[![Stargazers over time](https://starchart.cc/llody55/udocker.svg)](https://github.com/llody55/udocker)