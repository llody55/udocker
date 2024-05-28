import os
import docker
import subprocess

def test():
    app = subprocess.run(["curl --unix-socket /var/run/docker.sock http://localhost/version"], shell=True,check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("测试套接字",app.stdout.decode('utf-8'))
    client = docker.from_env()
    client.ping
    clients = docker.DockerClient(base_url='unix://var/run/docker.sock')
    clients.ping

if __name__ == '__main__':
    test()