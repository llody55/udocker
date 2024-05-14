import json
import paramiko
from threading import Thread
from channels.generic.websocket import WebsocketConsumer
from urllib.parse import parse_qs
from apps.models import *

# 错误追踪模块
import traceback,sys

class StreamConsumer(object):
    def __init__(self, websocket):
        self.websocket = websocket
        self.zmodem = False
        self.zmodemOO = False
    def connect(self,host_ip,host_port,sys_user_name,sys_user_passwd,term='xterm',cols=140, rows=50):
        #实例化SSHClient
        ssh_client = paramiko.SSHClient()
        #当远程服务器没有本地主机的密钥时自动添加到本地，这样不用在建立连接的时候输入yes或no进行确认
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            #连接ssh服务器，这里是以账号密码方式进行确认
            ssh_client.connect(host_ip,host_port,sys_user_name,sys_user_passwd,timeout=10)
            print("连接成功")
        except Exception as e:
            message  = str(e)
            #self.websocket.send是服务端给客户端发送消息
            self.websocket.send(message)
            print("连接失败",e)
            self.close()
            return False
        #打开ssh通道，建立长连接
        transport = ssh_client.get_transport()
        #建立会话session
        self.ssh_channel = transport.open_session()
        #获取终端，并设置term和终端大小,width终端宽度，height终端高度
        self.ssh_channel.get_pty(term=term,width=cols,height=rows)
        #激活终端，这样就可以正常登录了
        self.ssh_channel.invoke_shell()
        msg = f"Welcome to {sys_user_name}@{host_ip} \r\n"
        self.websocket.send(msg)
        # 一开始展示Linux欢迎相关内容,后面不进入此方法
        for i in range(2):
            mess = self.ssh_channel.recv(1024).decode('utf-8','ignore')
            message = json.dumps({'flag': 'success', 'message': mess})
            self.send_to_ws_mes(message)
    
    #断开websocket和关闭ssh通道
    def close(self):
        try:
            self.websocket.close()
            self.ssh_channel.close()
        except Exception as e:
            pass
    #发送消息到ws
    def send_to_ws_mes(self,event):
        #字符串转换字典
        text_data = json.loads(event)
        message = text_data['message']
        self.websocket.send(message)
    
    #从websocket接收的数据发送到ssh
    def _ws_to_ssh(self,data):
        try:
            self.ssh_channel.send(data)
        except OSError as e:
            self.close()
    
    #ssh返回的数据输出给websocket
    def _ssh_to_ws(self):
        try:
            while not self.ssh_channel.exit_status_ready():
                # #需要转码为utf-8形式
                data = self.ssh_channel.recv(1024).decode('utf-8')
                message = {'flag': 'success', 'message': data}
                if len(data) != 0:
                    self.send_to_ws_mes(json.dumps(message))
                else:
                    break
                
        except Exception as e:
            message = {'flag': 'error', 'message': str(e)}
            self.send_to_ws_mes(json.dumps(message))
            self.close()
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_details = {
                                    'filename': exc_traceback.tb_frame.f_code.co_filename,
                                    'lineno'  : exc_traceback.tb_lineno,
                                    'name'    : exc_traceback.tb_frame.f_code.co_name,
                                    'type'    : exc_type.__name__,
                                    'message'   : str(e) }  
                                    
            del(exc_type, exc_value, exc_traceback)
            
            print(traceback_details)


    def shell(self, data):
        Thread(target=self._ws_to_ssh, args=(data,)).start()
        Thread(target=self._ssh_to_ws).start()


    #前端传过来的数据会加个flag，如果flag是resize，则调用resize_pty方法来动态调整窗口的大小，否则就正常调用执行命令的方法
    def resize_pty(self, cols, rows):
        self.ssh_channel.resize_pty(width=cols, height=rows)
    

# 继承WebsocketConsumer 类
class SSHConsumer(WebsocketConsumer):
    def connect(self):
        # 有客户端来向后端发起websocket连接的请求时，自动触发
        query_params = parse_qs(self.scope["query_string"].decode())
        # 获取前端传递的ID
        host_address = query_params.get("host_address", [""])[0]
        print("前端传入：",host_address)
        # 通过ID在数据库中查出用于认证的信息并建立连接
        host_ssh = HostMonitoring.objects.get(host_address=host_address)
        self.host_ip = host_ssh.host_address
        self.host_name = host_ssh.host_address
        self.host_port = host_ssh.host_port
        self.sys_user_name = host_ssh.host_username
        self.sys_user_passwd = host_ssh.host_password
        #accept表示服务端允许和客户端创建连接.
        self.accept()


        self.ssh = StreamConsumer(websocket=self)
        self.ssh.connect(self.host_ip,self.host_port,self.sys_user_name,self.sys_user_passwd)


    def disconnect(self, close_code):
        #客户端与服务端断开连接时，自动触发（客户端断开，服务端也得断开）
        self.ssh.close()


    def receive(self, text_data=None):
        #浏览器基于websocket向后端发送数据，自动触发接收消息。
        #text_data是从客户端端(websocket)接收到的消息
        text_data = json.loads(text_data) #str转换为dict
        if text_data.get('flag') == 'resize': #如果为resize是改变终端通道的大小
            self.ssh.resize_pty(cols=text_data['cols'], rows=text_data['rows'])
        else:#否则正常执行命令
            data = text_data.get('entered_key', '')
            self.ssh.shell(data=data)