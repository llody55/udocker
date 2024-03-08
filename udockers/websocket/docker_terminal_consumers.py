import json
from threading import Thread
from channels.generic.websocket import WebsocketConsumer,AsyncWebsocketConsumer
from urllib.parse import parse_qs

# 引用验证是否开启TLS认证的公共模块
from apps.docker_mod import connect_to_docker

class TerminalConsumer(WebsocketConsumer):
    def send_prompt(self):
        prompt = f"[root@{self.container.attrs['Config']['Hostname']}]# "
        self.send(json.dumps({"type": "stdout", "data": prompt}))
    def connect(self):
        # 解析查询参数来获取容器ID
        query_string = parse_qs(self.scope["query_string"].decode())
        container_id = query_string.get('container_id', [None])[0]
        print("容器ID：",container_id)
        if container_id is None:
            self.close(code=4000)
            return

        success, client = connect_to_docker()
        if success:
            self.accept()
            try:
                self.container = client.containers.get(container_id)
                self.send(json.dumps({"type": "stdout", "data": "===================连接成功===================== \r\n"}))
                self.send_prompt()
            except Exception as e:
                self.close(code=4002)
        else:
            self.close(code=4001)
    def receive(self, text_data):
        # 处理从客户端接收的数据
        data = json.loads(text_data)
        command = data.get('command')

        if command.strip() == '':
            self.send_prompt()
        else:
            # 在一个新线程中执行命令，以避免阻塞WebSocket
            Thread(target=self.execute_command, args=(command,)).start()

    def execute_command(self, command):
        try:
            # 检查容器是否在运行
            if self.container.status != 'running':
                # 如果容器不是运行状态，则发送错误信息并返回
                self.send_output("Container is not running.")
                return
            
            # 执行命令
            exec_result = self.container.exec_run(cmd=command, stdout=True, stderr=True, stdin=False, tty=True, demux=True)
            stdout, stderr = exec_result.output

            # 如果有标准输出，则发送标准输出
            if stdout:
                self.send_output(stdout.decode('utf-8'))
                self.send_prompt()

            # 如果有标准错误，则发送标准错误
            if stderr:
                self.send_output(stderr.decode('utf-8'), error=True)

        except Exception as e:
            self.send_output(str(e), error=True)

    def send_output(self, message, error=False):
        # 发送终端输出
        message_type = 'stderr' if error else 'stdout'
        self.send(text_data=json.dumps({'type': message_type, 'data': message}))