# consumers.py
import json
import docker
from apps import docker_mod
from channels.generic.websocket import WebsocketConsumer
from apps.models import CustomUser,Role,Registries,HostMonitoring
# 引用验证是否开启TLS认证的公共模块
from apps.docker_mod import connect_to_docker
from loguru import logger

class DockerPullConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()

    def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        image_name = text_data_json['image_name']
        registry_url = text_data_json['registry_url']
        reg = Registries.objects.get(registries_url=registry_url)
        if reg.registries_auth:
            username = reg.registries_username
            # 解密存储的密码
            encrypted_password = reg.registries_password
            key = reg.encryption_key
            # 使用存储的密钥解密密码
            raw_password = docker_mod.decrypt_password(encrypted_password, key)
            # 同步方法
            # 容器管理模块API
            logger.error(image_name)
            success, client = docker_mod.connect_to_docker()
            if success:
                # 登录私有镜像仓库
                login_result = client.login(username, raw_password, registry=registry_url)
                print("登录结果：", login_result)
                for line in client.api.pull(image_name, stream=True, decode=True):
                    self.send(text_data=json.dumps({
                        'message': line
                    }))
        else:
            success, client = connect_to_docker()
            if success:
                for line in client.api.pull(image_name, stream=True, decode=True):
                    self.send(text_data=json.dumps({
                        'message': line
                    }))