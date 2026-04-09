import json
import docker
import dockerpty
from threading import Thread, Event
from channels.generic.websocket import WebsocketConsumer
from urllib.parse import parse_qs
import time
import os
import sys
import io

# 引用验证是否开启TLS认证的公共模块
from apps.docker_mod import connect_to_docker

class ProxyConsumer(WebsocketConsumer):
    stop_event = None
    client = None
    container = None
    socket = None
    output_thread = None
    input_thread = None
    
    def connect(self):
        print("=== WebSocket连接开始 ===")
        # 从连接的查询参数中获取容器ID和其他参数
        try:
            self.query_params = parse_qs(self.scope['query_string'].decode())
            self.container_id = self.query_params.get('container', [''])[0]
            self.workdir = self.query_params.get('workdir', ['/'])[0]
            self.shell_command = self.query_params.get('cmd', ['/bin/sh'])[0]  # 默认使用 /bin/sh
            print("接收数据:", self.query_params)
            print(f"容器ID: {self.container_id}")
            print(f"工作目录: {self.workdir}")
            print(f"Shell命令: {self.shell_command}")
        except Exception as e:
            print(f"解析查询参数失败: {e}")
            self.close()
            return
        
        # 初始化 Docker 客户端
        try:
            print("尝试连接Docker守护进程...")
            success, self.client = connect_to_docker()
            if not success:
                print("无法连接到Docker守护进程")
                self.close()
                return
            print("成功连接到Docker守护进程")
        except Exception as e:
            print(f"连接Docker失败: {e}")
            self.close()
            return

        # 获取容器
        try:
            print(f"尝试获取容器: {self.container_id}")
            self.container = self.client.containers.get(self.container_id)
            print(f"成功获取容器: {self.container.name}")
        except docker.errors.NotFound:
            print(f"No such container: {self.container_id}")
            self.close()
            return
        except docker.errors.APIError as e:
            print(f"Server error: {e}")
            self.close()
            return
        
        # 接受WebSocket连接
        print("接受WebSocket连接...")
        self.accept()
        print("WebSocket连接已接受")
        
        # 启动事件和线程
        self.stop_event = Event()
        
        # 创建并启动容器的交互式shell
        try:
            print("创建容器的交互式shell...")
            # 使用socket=True获取底层socket连接
            exec_result = self.container.exec_run(
                cmd=[self.shell_command],
                stdin=True,
                stdout=True,
                stderr=True,
                tty=True,
                socket=True,
                workdir=self.workdir
            )
            # 正确获取socket对象
            self.socket = exec_result.output
            print("成功创建交互式shell")
            
            # 启动输出处理线程
            print("启动输出处理线程...")
            self.output_thread = Thread(target=self.handle_output)
            self.output_thread.daemon = True
            self.output_thread.start()
            print("输出处理线程已启动")
            
            # 启动输入处理线程
            print("启动输入处理线程...")
            self.input_thread = Thread(target=self.handle_input)
            self.input_thread.daemon = True
            self.input_thread.start()
            print("输入处理线程已启动")
        except Exception as e:
            print(f"创建交互式shell失败: {e}")
            self.close()
            return
        
        print("=== WebSocket连接建立完成 ===")
    
    def disconnect(self, close_code):
        # 停止所有线程
        if self.stop_event:
            self.stop_event.set()
        
        
        # 等待线程结束
        if hasattr(self, 'output_thread') and self.output_thread and self.output_thread.is_alive():
            self.output_thread.join(timeout=1)
        if hasattr(self, 'input_thread') and self.input_thread and self.input_thread.is_alive():
            self.input_thread.join(timeout=1)
        
        print("=== WebSocket连接已关闭 ===")
    
    def receive(self, text_data=None, bytes_data=None):
        if text_data:
            # 直接将输入写入容器
            if hasattr(self, 'socket') and self.socket:
                try:
                    # 发送输入到容器
                    self.socket._sock.send(text_data.encode('utf-8'))
                except Exception as e:
                    print(f"写入输入失败: {e}")
    
    def handle_output(self):
        """处理容器输出并发送到WebSocket"""
        while not self.stop_event.is_set():
            try:
                if hasattr(self, 'socket') and self.socket:
                    # 实时读取容器输出
                    data = self.socket._sock.recv(1024)
                    if data:
                        # 发送输出到WebSocket
                        self.send(text_data=data.decode('utf-8', errors='ignore'))
                    else:
                        # 连接已关闭
                        break
                else:
                    break
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"读取输出失败: {e}")
                break
    
    def handle_input(self):
        """处理输入（保持线程运行，实际输入由receive方法处理）"""
        while not self.stop_event.is_set():
            try:
                # 短暂休眠，避免CPU占用过高
                time.sleep(0.1)
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"处理输入失败: {e}")
                break