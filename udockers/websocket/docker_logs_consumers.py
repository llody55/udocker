from threading import Thread
from channels.generic.websocket import WebsocketConsumer
from docker.errors import NotFound
from urllib.parse import parse_qs

# 引用验证是否开启TLS认证的公共模块
from apps.docker_mod import connect_to_docker

# 多线程
class DockerStreamThread(Thread):
    def __init__(self, websocket, conn_stream):
        Thread.__init__(self)
        self.websocket = websocket
        self.stream = conn_stream

    def run(self):
        self.websocket.accept()  # 接受WebSocket连接
        for line in self.stream:
            # 读取流的输出，发送到websocket（前端）
            self.websocket.send(line.decode())
        else:
            self.websocket.close()

class DockerLogConsumer(WebsocketConsumer):
    def connect(self):
        query_params = parse_qs(self.scope["query_string"].decode())
        self.containers = query_params.get("containers", [""])[0]
        try:
            success, client = connect_to_docker()
            if success:
                container = client.containers.get(self.containers)
                self.conn_stream = container.logs(stream=True, follow=True,tail=500)
                # 开启线程获取日志并发送到WebSocket
                thread = DockerStreamThread(self, self.conn_stream)
                thread.start()
            else:
                print("无法连接到Docker守护进程。")
        except NotFound:
            self.send(text_data='Container not found')
            self.close()