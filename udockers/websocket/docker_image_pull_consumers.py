# consumers.py
import json
import docker
from apps import docker_mod
from channels.generic.websocket import WebsocketConsumer
from apps.models import CustomUser,Role,Registries,HostMonitoring
# 引用验证是否开启TLS认证的公共模块
from apps.docker_mod import connect_to_docker
from docker.errors import APIError, ImageNotFound,NotFound,DockerException
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
            # logger.error(image_name)
            success, client = docker_mod.connect_to_docker()
            if success:
                try:
                    # 登录私有镜像仓库
                    login_result = client.login(username, raw_password, registry=registry_url)
                    if login_result.get('Status') != 'Login Succeeded':
                        raise DockerException('登录失败，请检查用户名和密码。')
                    for line in client.api.pull(image_name, stream=True, decode=True):
                        self.send(text_data=json.dumps({
                            'message': line
                        }))
                except NotFound as e:
                    self.send(text_data=json.dumps({'error': '镜像未找到，请检查镜像名称或tag。'}))
                except APIError as e:
                    logger.error(e)
                    if e.status_code == 500 and "You may not login yet" in str(e):
                        self.send(text_data=json.dumps({'error': f'连接被拒绝：您可能尚未登录,或者登录信息不正确!!!'}))
                    else:
                        self.send(text_data=json.dumps({'error': f'发生错误: {str(e)}'}))
                except DockerException as e:
                    self.send(text_data=json.dumps({'error': f'登录错误: {str(e)}'}))
                except Exception as e:
                    self.send(text_data=json.dumps({'error': f'发生错误: {str(e)}'}))
        else:
            success, client = connect_to_docker()
            if success:
                try:
                    for line in client.api.pull(image_name, stream=True, decode=True):
                        self.send(text_data=json.dumps({
                            'message': line
                        }))
                except NotFound as e:
                    self.send(text_data=json.dumps({'error': '镜像未找到，请检查镜像名称或tag。'}))
                except APIError as e:
                    logger.error(e)
                    if e.status_code == 500 and "You may not login yet" in str(e):
                        self.send(text_data=json.dumps({'error': f'连接被拒绝：您可能尚未登录,或者登录信息不正确!!!'}))
                except Exception as e:
                    self.send(text_data=json.dumps({'error': f'发生错误: {str(e)}'}))