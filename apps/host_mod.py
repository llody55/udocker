import os
import stat
import paramiko
import traceback
# 主要使用在获取文件时间处
import datetime as dtime
from .models import HostMonitoring
from apps import docker_mod
from cryptography.fernet import Fernet
# 多线程
from concurrent.futures import ThreadPoolExecutor

# 主机sftp登录方法
class SSHConnectionManager:
    def __init__(self):
        self.connections = {}

    def get_connection(self, host_address):
        if host_address not in self.connections:
            host_ssh = HostMonitoring.objects.get(host_address=host_address)
            host_ip = host_ssh.host_address
            host_port = int(host_ssh.host_port)
            sys_user_name = host_ssh.host_username
            encrypted_password = host_ssh.host_password
            key = host_ssh.host_encryption_key
            sys_user_passwd = docker_mod.decrypt_password(encrypted_password, key)

            transport = paramiko.Transport((host_ip, host_port))
            transport.connect(username=sys_user_name, password=sys_user_passwd)
            self.connections[host_address] = transport

        return self.connections[host_address]

    def close_all_connections(self):
        for transport in self.connections.values():
            transport.close()
        self.connections.clear()

# 单例模式的SSH连接管理器
ssh_manager = SSHConnectionManager()

# 用于判断用户删除的是文件还是文件夹
def delete_file_or_folder(sftp_client, path):
    try:
        # 获取文件或文件夹的属性
        attrs = sftp_client.stat(path)
        
        # 判断是否为文件夹（目录）
        if attrs.st_mode & stat.S_ISDIR(attrs.st_mode):
            # 如果是文件夹，则递归删除其内容
            for item in sftp_client.listdir(path):
                if item not in ('.', '..'):
                    # 递归调用 delete_file_or_folder 函数，删除子项
                    delete_file_or_folder(sftp_client, f"{path}/{item}")
            # 删除空的文件夹
            sftp_client.rmdir(path)
        else:
            # 如果是文件，则直接删除文件
            sftp_client.remove(path)
    except FileNotFoundError:
        # 如果文件或文件夹不存在，忽略该异常，继续执行
        pass  

# 文件单位换算器
def human_read_format(size):
    # 定义转换为易读格式的函数
    if size < 1024:
        # 大小小于1K时，显示为B
        return f"{size} B"
    elif size < 1024**2:
        # 大小1K到1M之间时，显示为KB
        return f"{round(size/1024, 2)} KB"
    elif size < 1024**3:
        # 大小1M到1G之间时，显示为MB
        return f"{round(size/1024**2, 2)} MB"
    else:
        # 大小在1G以上时，显示为GB
        return f"{round(size/1024**3, 2)} GB"

# 获取文件列表信息
def fetch_file_info(executor, ssh, path, fileattr):
    if stat.S_ISDIR(fileattr.st_mode):
        size = None  # Is a directory, size set to None
    else:
        size = human_read_format(fileattr.st_size)  # If it's not a directory, convert to an easily readable format

    permission = stat.filemode(fileattr.st_mode)
    # 获取所有的Uid其实没必要
    # owner_future = executor.submit(get_owner_name, ssh, fileattr.st_uid)
    # 获取当前的目录UID即可
    owner_future = fileattr.st_uid

    return {
            'name': fileattr.filename,
            'date': dtime.datetime.fromtimestamp(fileattr.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'size': size,
            'owner_future': owner_future, 
            'permissions': permission,
            # 'permissions': oct(fileattr.st_mode)[-3:],
            'isFolder': stat.S_ISDIR(fileattr.st_mode),
        }