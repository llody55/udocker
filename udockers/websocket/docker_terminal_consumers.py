import json
import docker
from threading import Thread
from channels.generic.websocket import WebsocketConsumer,AsyncWebsocketConsumer
from urllib.parse import parse_qs

# 引用验证是否开启TLS认证的公共模块
from apps.docker_mod import connect_to_docker

class ProxyConsumer(WebsocketConsumer):
    exec_id = None
    def connect(self):
        # 从连接的查询参数中获取容器ID和其他参数
        self.query_params = parse_qs(self.scope['query_string'].decode())
        self.container_id = self.query_params.get('container', [''])[0]
        self.workdir = self.query_params.get('workdir', ['/'])[0]
        self.shell_command = self.query_params.get('cmd', ['/bin/sh'])[0]  # 默认使用 /bin/sh
        print("接收数据:",self.query_params)
        

        # 初始化 Docker 客户端
        self.client = docker.from_env()
        # 确保self.client是一个DockerClient实例
        if not isinstance(self.client, docker.client.DockerClient):
            print("connect_to_docker didn't return a DockerClient instance.")
            # 在这里你可能想关闭连接或抛出异常
            self.close()
            return

        # 获取容器
        try:
            self.container = self.client.containers.get(self.container_id)
            print("容器值：",self.container)
        except docker.errors.NotFound:
            print(f"No such container: {self.container_id}")
            self.close()
            return
        except docker.errors.APIError as e:
            print(f"Server error: {e}")
            self.close()
            return
        
        # 创建一个 Docker 执行实例
        exec_instance = self.container.exec_run(
            cmd=self.shell_command,
            stdin=True,
            tty=True,
            detach=True
        )
        self.exec_id = exec_instance['Id']
        print("ID：",self.exec_id)
        # 接受WebSocket连接
        self.accept()
    def disconnect(self, close_code):
        # 关闭Docker执行实例
        if self.exec_id:
            self.client.api.exec_resize(self.exec_id, height=20, width=80) # 重置为默认大小，以避免影响下次执行
            # 这里可能需要进一步的逻辑来关闭exec实例

    def receive(self, text_data=None, bytes_data=None):
        if not self.exec_id:
            return

        if text_data:
            # 将接收到的文本数据发送到Docker exec的stdin
            self.client.api.exec_start(self.exec_id, detach=False, tty=True, stdin=True, input=text_data)

        # 这里我们假设我们需要实时读取输出
        # 它可能需要在另一个线程或异步环境中运行以避免阻塞
        output = self.client.api.exec_start(self.exec_id, stream=True, tty=True)
        for chunk in output:
            self.send(text_data=chunk.decode('utf-8'))