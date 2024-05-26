# udocker
<p align="center"><a href="#"><img src="https://static.llody.top/images/DM_20240323220512_001.png" alt="Image"></a></p>

**一个更简洁的Docker面板**

<div align="center">
<a href="https://github.com/llody55/udocker" target="_blank"><img alt="Github stars" src="https://img.shields.io/github/stars/llody55/udocker.svg" title="给个start吧，求求了"></a>
<img src="https://camo.githubusercontent.com/f8defc7b1662a63895c0de6aa7820bd10b5de2d725b307d76cae5e5c96b9e15c/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f646f636b65722d3132333435363f6c6f676f3d646f636b6572266c6f676f436f6c6f723d666666266c6162656c436f6c6f723d316337616564"alt="docker" data-canonical-src="https://img.shields.io/badge/docker-123456?logo=docker&logoColor=fff&labelColor=1c7aed">
<img id="wechatIcon" alt="微信公众号" src="https://img.shields.io/badge/%E5%BE%AE%E4%BF%A1%E5%85%AC%E4%BC%97%E5%8F%B7-%E8%BF%90%E7%BB%B4%E5%AE%9E%E8%B7%B5%E5%BD%95-brightgreen" style="max-width: 100%;" title="给个关注吧，求求了">
</div>

> **声明:** 此项目当前为base版，请勿暴露于公网环境，可能引发安全问题
**如果此项目对你有用，请给一个**:star:

## 资源
> 只需要：1核1G即可，暂时只有X86版本

## 快速了解
> udocker 是一个轻量级且好用的docker管理面板，并且自带一个webssh终端管理工具,可以很方便的管理服务器和上传下载文件。

目前支持的功能有：

   - 镜像管理
   - 容器管理
   - 网络管理
   - 存储管理
   - 事件中心
   - 多语言(中英切换)
   - webssh终端
   - Linux文件管理器

## 安装与部署(推荐)
```
docker run -itd --name udocker -p 8000:8000 -p 9002:9002 -v /var/run/docker.sock:/var/run/docker.sock  llody/udocker:v1.1-base
```
> 默认账户：llody 密码：1qaz2wsx
## 预览
![1](./docs/images/1.png)
![2](./docs/images/2.png)
![3](./docs/images/3.jpg)
![4](./docs/images/4.jpg)
![5](./docs/images/5.jpg)
![6](./docs/images/6.jpg)
![7](./docs/images/7.jpg)
![8](./docs/images/8.png)
![9](./docs/images/9.jpg)
![10](./docs/images/10.jpg)
![11](./docs/images/11.png)
![12](./docs/images/12.jpg)
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

## Star趋势
[![Stargazers over time](https://starchart.cc/llody55/udocker.svg)](https://github.com/llody55/udocker)