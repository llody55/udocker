import psutil
import docker
from docker.errors import DockerException, TLSParameterError,APIError
from docker.tls import TLSConfig
from cryptography.fernet import Fernet
from django.contrib.auth.hashers import check_password

# 公用连接方法
def connect_to_docker():
    try:
        client = docker.from_env()
        client.ping()
        return True, client
    except DockerException as e:
        error_message = str(e)
        if '400 Client Error' in error_message and "Client sent an HTTP request to an HTTPS server." in error_message:
            msg = f"Docker开启TLS认证，无权限连接或配置错误。"
        else:
            # 处理非400错误
            msg = f"连接失败，错误信息: {error_message}"
        
        print(msg)  # 输出错误信息
        return False, None

# 检查Docker连接的函数，无需TLS验证
def check_docker_connections():
    try:
        # 尝试连接Docker守护进程
        client = docker.from_env()
        client.ping()  # 如果能ping通，说明连接成功
        return True
    except DockerException as e:
        print(f'连接到Docker守护进程失败: {e}')
        return False
    except Exception as e:
        print(f'连接到Docker守护进程失败: {e}')
        return False

# 流量字节单位转换
def convert_bytes(bytes_num):
    """
    将字节数转换为 K 或 M
    :param bytes_num: 流量的字节数
    :return: 转换后的流量值和单位（K 或 M）
    """
    if bytes_num < 1024:
        return "{}B".format(bytes_num)
    elif 1024 <= bytes_num < 1024**2:
        return "{:.2f}K".format(bytes_num / 1024)
    else:
        return "{:.2f}M".format(bytes_num / 1024**2)

# 验证镜像仓库的密码方法
def docker_validate_password(self, raw_password):
    return check_password(raw_password, self.registries_password)

# 加密
def encrypt_password(raw_password):
    # 你必须保存这个key，因为它会在解密时使用
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(raw_password.encode('utf-8'))
    return encrypted_password, key

# 解密
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    raw_password = cipher_suite.decrypt(encrypted_password).decode('utf-8')
    return raw_password

# 资源创建时间格式化
from datetime import date, timedelta
def timestamp_format(timestamp):
    c = timestamp + timedelta(hours=8)
    t = date.strftime(c, '%Y-%m-%d %H:%M:%S')
    return t

def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def get_memory_usage():
    total_memory = psutil.virtual_memory().total
    used_memory = psutil.virtual_memory().used
    return total_memory, used_memory

def get_disk_usage():
    total_disk_space = psutil.disk_usage('/').total
    used_disk_space = psutil.disk_usage('/').used
    return total_disk_space, total_disk_space - used_disk_space
