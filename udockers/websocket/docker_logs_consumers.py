from threading import Thread, Event
from channels.generic.websocket import WebsocketConsumer
from docker.errors import NotFound
from urllib.parse import parse_qs

# 引用验证是否开启TLS认证的公共模块
from apps.docker_mod import connect_to_docker

# 多线程
class DockerStreamThread(Thread):
    def __init__(self, websocket, conn_stream, stop_event):
        Thread.__init__(self)
        self.websocket = websocket
        self.stream = conn_stream
        self.stop_event = stop_event

    def run(self):
        # 开启连接
        self.websocket.accept()
        try:
            # 循环日志
            for line in self.stream:
                # 如果有停止事件 就直接中断，避免因为前端关闭连接导致后端卡死情况
                if self.stop_event.is_set():
                    break
                self.websocket.send(line.decode())
        finally:
            self.websocket.close()

class DockerLogConsumer(WebsocketConsumer):
    def connect(self):
        self.stop_event = Event()
        query_params = parse_qs(self.scope["query_string"].decode())
        self.containers = query_params.get("containers", [""])[0]
        try:
            success, client = connect_to_docker()
            if success:
                container = client.containers.get(self.containers)
                self.conn_stream = container.logs(stream=True, follow=True,tail=500)
                # 开启线程获取日志并发送到WebSocket
                self.thread = DockerStreamThread(self, self.conn_stream,self.stop_event)
                self.thread.start()
            else:
                print("无法连接到Docker守护进程。")
                self.close(code=1011)
        except NotFound:
            self.send(text_data='Container not found')
            self.close()
    
    def disconnect(self, close_code):
        # 通知线程停止
        self.stop_event.set()
        # 确保关闭容器日志流
        if hasattr(self, 'conn_stream'):
            self.conn_stream.close()
        # 确保线程结束
        if self.thread.is_alive():
            self.thread.join()