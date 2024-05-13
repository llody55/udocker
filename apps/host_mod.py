import os
import stat
import paramiko
import traceback
# 主要使用在获取文件时间处
import datetime as dtime
from .models import HostMonitoring
# 多线程
from concurrent.futures import ThreadPoolExecutor


# 主机sftp登录方法
def get_sftp_client(host_ssh_id):
    # 通过ID在数据库中查出用于认证的信息并建立连接
    host_ssh = HostMonitoring.objects.get(id=host_ssh_id)
    host_ip = host_ssh.host_address
    host_port = int(host_ssh.host_port)
    sys_user_name = host_ssh.host_username
    sys_user_passwd = host_ssh.host_password
            
    # 建立SSH连接
    try:
        sftp_client = paramiko.SFTPClient(host_ip, host_port, sys_user_name, sys_user_passwd)
        sftp_client.connect()
        return True, sftp_client
    except Exception as e:
        print(f"Error connecting to host: {e}")
        traceback.print_exc()
        print("get_sftp_client 详细错误:", e)

    return False, None

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