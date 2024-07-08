# consumers.py
import json
import docker
from channels.generic.websocket import WebsocketConsumer
# 引用验证是否开启TLS认证的公共模块
from apps.docker_mod import connect_to_docker

class DockerPullConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()

    def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        image_name = text_data_json['image_name']

        success, client = connect_to_docker()
        if success:
            for line in client.api.pull(image_name, stream=True, decode=True):
                self.send(text_data=json.dumps({
                    'message': line
                }))