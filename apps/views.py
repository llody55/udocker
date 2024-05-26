import re
import os
import stat
import json
import uuid
import time
import docker
import datetime
import tempfile
import paramiko
import hashlib
import humanize
import ipaddress
import traceback
import concurrent.futures
from udockers.settings import VERSION_STR
from dateutil import parser
from django.http import HttpResponse,JsonResponse, QueryDict,FileResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login,logout 
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .models import CustomUser,Role,Registries,HostMonitoring
from django.contrib.auth.backends import ModelBackend
from django.db import IntegrityError, transaction
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.clickjacking import xframe_options_exempt
from django.shortcuts import get_object_or_404
from docker.types import IPAMPool, IPAMConfig
from loguru import logger
# Create your views here.
from apps import docker_mod,host_mod
from docker.errors import DockerException, TLSParameterError,APIError, ContainerError, ImageNotFound,NotFound
from django.utils.translation import gettext_lazy as _

@login_required
def index(request):
    if request.method == "GET":
        client = docker.from_env()
        #docker客户端版本信息
        client_version = client.version()['Version']
        # 服务端版本
        server_version = client.info()['ServerVersion']
        # Docker目录
        docker_dir = client.info()['DockerRootDir']
        # docker_compose 组件版本
        # docker_compose_version = subprocess.check_output(['docker-compose', '-v']).decode().strip()
        # print("docker_compose 组件版本",docker_compose_version)
        #docker平台
        Platform = client.version()['Platform']['Name']
        # 提取组件版本信息
        data = []
        for i in client.version()['Components']:
            components_name = i['Name']
            components_version = i['Version']
            components = "%s-%s" %(components_name,components_version)
            dat = {"components":components}
            data.append(dat)
        #许可证
        Product_License = client.version()['Platform']['Name']
        #go版本
        go_version = client.version()['GoVersion']
        #CPU核数
        CPU_info = client.info()['NCPU']
        #内存总数
        mem_total = client.info()['MemTotal']
        #格式化内存
        total_mem = round(mem_total / (1024*1024*1024), 2)
        # 主机hostname
        hostname = client.info()['Name']

        # CPU 架构和内核版本
        #CPU架构
        CPU_arch = client.info()['Architecture']
        #系统类型
        OS_type = client.info()['OSType']
        #内核版本
        kernel_version = client.info()['KernelVersion']
        #系统版本
        OS_system = client.info()['OperatingSystem']
                    
        # 系统时间
        system_time = client.info()['SystemTime']
        #总容器
        Containers_total = client.info()['Containers']
        #当前运行中的容器
        Containers_Running = client.info()['ContainersRunning']
        #格式化总容器于运行容器
        Containers = "%s/%s" %(Containers_Running,Containers_total)
        #暂停的容器
        Containers_Paused = client.info()['ContainersPaused']
        #停止的容器
        Containers_Stopped = client.info()['ContainersStopped']
        #镜像总数
        images = client.info()['Images']
        connect={"client_version":client_version,"server_version":server_version,"docker_dir":docker_dir,"data":data,"Product_License":Product_License,"go_version":go_version,"Platform":Platform,
                        "CPU_arch":CPU_arch,"OS_type":OS_type,"kernel_version":kernel_version,"OS_system":OS_system,"hostname":hostname,"system_time":system_time,
                        "Containers":Containers,"images":images,"CPU_info":CPU_info,"total_mem":total_mem}
    return render(request, 'docker_info.html',{"connect":connect})

# 登录
@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        print("当前用户:", user)
        if user is not None:
            # 获取用户所属的所有角色
            roles = user.roles.all()
            for role in roles:
                # 获取用户所属的所有角色，并存入session
                request.session['user_roles'] = role.name
                print(f"当前用户所在角色: {role.name}")
                # 获取当前角色的所有权限
                role_permissions = role.permissions.all()
                for perm in role_permissions:
                    print(f"当前角色所有权限: {perm.name}")
            # 检查用户是否有某个具体的权限（需要提供app_label）
            has_edit_permission = user.has_perm('edit_permission')
            print("是否有编辑权限:", has_edit_permission)
            login(request, user)
            return redirect('index')
        else:
            msg = "账户或者密码错误"
            return render(request, 'login.html',{"msg": msg})
    else:
        return render(request, 'login.html')

# 登出
@csrf_exempt
def user_logout(request):
    logout(request)
    # 重定向到登录页面，这里使用了Django的默认登录路由
    return redirect('/apps/user_login/')

# 重置密码
@csrf_exempt
@login_required
def password_reset_request(request):
    if request.method == "GET":
        return render(request, 'password_reset.html')
    elif request.method == "POST":
        # 当前用户
        username = request.POST.get('username')
        # 当前密码
        current_password = request.POST.get('current_password')
        # 新密码
        new_password = request.POST.get('new_password')
        print("前端提交信息:",username,current_password,new_password)
        user = authenticate(request, username=username, password=current_password)
        if user is not None:
            try:
                user.set_password(new_password)
                user.save()
                return JsonResponse({'success': '密码已重置，请重新登陆','code':'0'})
            except Exception as e:
                # 如果密码更新过程中出现异常，返回错误信息
                return JsonResponse({'error': '密码重置失败，请重试一次!!!','code':'1'})
        else:
            # 如果当前密码验证失败，返回错误信息
            return JsonResponse({'error': '当前密码不正确，请重试','code':'1'})

@csrf_exempt            
@login_required
def docker_container(request):
    return render(request, 'container/docker_container_list.html')


# 容器列表 API
@csrf_exempt
@login_required
def docker_container_api(request):
    if request.method == "GET":
        data = []
        search_key = request.GET.get("search_key")
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                containers = client.containers.list(all=True)
                for container in containers:
                    id = container.short_id
                    name = container.name
                    image = container.attrs['Config']['Image']
                    isrunning = container.attrs['State']['Running']
                    status = container.status
                    ports_data = []
                    for i in container.attrs['NetworkSettings']['Ports']:
                        ports = i
                        #该变量用于获取是否有未映射端口，没有为false，有为true
                        isport = False
                        host_port = None
                        if not container.attrs['NetworkSettings']['Ports'][i]:
                            ports = i
                            isport = True
                        else:
                            host_ip = container.attrs['NetworkSettings']['Ports'][i][0]['HostIp']
                            if not container.attrs['NetworkSettings']['Ports'][i][0]['HostPort']:
                                host_port = None
                            else:
                                host_port = container.attrs['NetworkSettings']['Ports'][i][0]['HostPort']
                            
                        dat = {"ports":ports,"isport":isport,"host_port":host_port}
                        ports_data.append(dat)
                    # 获取容器的重启策略
                    restart_policy = container.attrs['HostConfig']['RestartPolicy']['Name']
                    # 获取容器的重启次数
                    restart_count = container.attrs['RestartCount']
                    # 确定开关按钮的状态，'always'则为开启，其它情况则为关闭
                    restart_switch = restart_policy == 'always'
                    # 获取容器配置中的健康检查状态
                    healthcheck = container.attrs['Config'].get('Healthcheck', None)
                    if healthcheck:
                        # 如果存在健康检查配置
                        health_data = container.attrs['State'].get('Health', None)
                        if health_data:
                            # 获取健康检查的当前状态
                            health_status = health_data.get('Status', '未知')
                            # print(f"健康检查状态: {health_status}")
                        else:
                            health_status = None
                    else:
                        health_status = None
                    time_str = container.attrs['Created']
                    time_offset = datetime.timedelta(hours=8)
                    time_obj = parser.isoparse(time_str)
                    time_obj += time_offset
                    create_time = time_obj.strftime('%Y-%m-%d %H:%M:%S')
                    dat = {"id":id,"name":name,"image":image,"isrunning":isrunning,"restart_switch":restart_switch,"restart_count":restart_count,"status":status,"create_time":create_time,"ports_data":ports_data,"health_status":health_status}
                    # 根据查询关键字返回数据
                    if search_key:
                        if search_key in name:
                            data.append(dat)
                    else:
                        data.append(dat)
                code = 0
                msg = "查询成功."
            else:
                print("无法连接到Docker守护进程。")
        except Exception as e:
            print(e)
            code = 1
            msg = "查询失败."
        # 分页
        count = len(data)  # 要在切片之前获取总数

        if request.GET.get('page'):  # 如果为真说明数据表格带有分页（适配首页命名空间选择）
            page = int(request.GET.get('page'))
            limit = int(request.GET.get('limit'))
            # data = data[0:10]
            start = (page - 1) * limit  # 切片的起始值
            end = page * limit  # 切片的末值
            data = data[start:end]  # 返回指定数据范围

        result = {'code': code, 'msg': msg, 'data': data, 'count': count}
        return JsonResponse(result)
    elif request.method == "POST":
        data = []
        # 获取表单数据
        name = request.POST.get("name")
        registries = request.POST.get("registries")
        images = request.POST.get("images")
        # full_image_name  = f"{registries}/{images}"
        # 端口映射
        hostPorts = request.POST.getlist("hostPorts[]")
        containerPorts = request.POST.getlist("containerPorts[]")
        protocols = request.POST.getlist("protocols[]")
        port_bindings = {}
        if hostPorts and containerPorts and protocols:
            for container_port, host_port, protocol in zip(containerPorts, hostPorts, protocols):
                port_bindings[container_port + '/' + protocol.lower()] = host_port
        # 命令
        command = request.POST.get("command")
        # 挂载映射
        host_volumes = request.POST.getlist("host_volumes[]")
        host_container_volumes = request.POST.getlist("host_container_volumes[]")
        docker_volumes = request.POST.getlist("docker_volumes[]")
        docker_container_volumes = request.POST.getlist("docker_container_volumes[]")
        volume_bindings = {}
        if host_volumes and host_container_volumes:
            for host_volume, host_container_volume in zip(host_volumes, host_container_volumes):
                if host_volume:
                    volume_bindings[host_volume] = {'bind': host_container_volume, 'mode': 'rw'}

        if docker_volumes and docker_container_volumes:
            for docker_volume, docker_container_volume in zip(docker_volumes, docker_container_volumes):
                if docker_volume:
                    # 假设docker_volume是已创建的数据卷名称
                    volume_bindings[docker_volume] = {'bind': docker_container_volume, 'mode': 'rw'}

        # 网络模式
        network_mode = request.POST.get("driver")
        # 环境变量
        keyName = request.POST.getlist("keyName[]")
        valueName = request.POST.getlist("valueName[]")
        env_vars = None
        if keyName and valueName:
            env_vars = {key: value for key, value in zip(keyName, valueName) if value}
        # 重启策略
        restart_policy = request.POST.get("restart_policy")
        container = None
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                container = client.containers.create(
                    image=images,
                    name=name,
                    network_mode=network_mode,
                    ports=port_bindings if port_bindings else None,
                    volumes=volume_bindings if volume_bindings else None,
                    environment=env_vars if env_vars else None,
                    command=command if command else None,
                    restart_policy={"Name": restart_policy} if restart_policy else None,
                    detach=True,
                    tty=True,
                    stdin_open=True
                )
                container.start()
            code = 0
            msg = "创建成功"
        except (ImageNotFound, ContainerError, APIError, DockerException, Exception) as e:
            # 设置错误状态码和消息
            code = 1
            if isinstance(e, ImageNotFound):
                msg = f"创建失败：镜像未找到,请先在【镜像管理】中拉取镜像 {e}"
            elif isinstance(e, ContainerError):
                msg = f"创建失败：容器运行错误 {e}"
            elif isinstance(e, APIError):
                error_message = str(e)
                if 'port is already allocated' in error_message:
                    # 如果错误信息中包含“port is already allocated”，则可以判断为端口冲突
                    msg = "创建失败：端口冲突，指定的端口已被占用。"
                elif e.is_client_error():
                    msg = f"创建失败：客户端错误，请检查发送的数据是否正确 {e}"
                elif e.is_server_error():
                    msg = f"创建失败：服务器错误，Docker守护进程无法处理请求 {e}"
                else:
                    msg = f"创建失败：Docker API 错误 {e}"
            elif isinstance(e, DockerException):
                msg = f"创建失败：Docker异常 {e}"
            else:
                msg = f"创建失败：未知错误 {e}"

            # 现在的异常处理逻辑
            logger.error(msg)

            # 清理代码，尝试删除创建失败的容器
            if container:
                try:
                    container.remove(force=True)
                    logger.info(f"清理：容器 {container.short_id} 因创建失败，已被删除。")
                except NotFound:
                    # 容器不存在，无须清理
                    pass
                except DockerException as cleanup_error:
                    # 删除容器时出现了问题
                    logger.error(f"清理失败：无法删除容器 {container.short_id}，原因：{cleanup_error}")

        # 返回响应到客户端
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)
    elif request.method == "CLEAR":
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                containers = client.containers.list(all=True)
                for container in containers:
                    status = container.status
                    if status != 'running':
                        con_restart = client.containers.get(container.name)
                        con_restart.remove(force=True)  
                        print("清理容器：",container.name)
            code = 0
            msg = "清理成功"
        except DockerException as e:
            logger.error(e)
            code = 1
            msg = f"报错了：{e}"
        
        # 返回响应到客户端
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)

# docker容器详情信息API
@csrf_exempt
@xframe_options_exempt
@login_required
def docker_container_info(request):
    name = request.GET.get("name")
    print("容器名称:",name)
    connect = {}  # 初始化连接字典
    try:
        success, client = docker_mod.connect_to_docker()
        if success:
            containers = client.containers.list(all=True)
            for container in containers:
                if name == container.name:
                    #对象ID，截断为12个字符
                    id = container.short_id
                    #name
                    name = container.name
                    #运行状态
                    isrunning = container.attrs['State']['Running']
                    #运行状态
                    status = container.status
                    #创建时间
                    create_time = container.attrs['Created']
                    #运行时间
                    start_time = container.attrs['State']['StartedAt']

                    # 系统时间
                    system_time = client.info()['SystemTime']

                    #容器详细信息
                    #image
                    image = container.attrs['Config']['Image']
                    #端口
                    ports_data = []
                    # 当端口未映射时，设置默认值为none
                    host_port = None
                    for i in container.attrs['NetworkSettings']['Ports']:
                        ports = i
                        #该变量用于获取是否有未映射端口，没有为false，有为true
                        isport = False
                        if not container.attrs['NetworkSettings']['Ports'][i]:
                            ports = i
                            isport = True
                        else:
                            host_ip = container.attrs['NetworkSettings']['Ports'][i][0]['HostIp']
                            host_port = container.attrs['NetworkSettings']['Ports'][i][0]['HostPort']
                        dat = {"ports":ports,"isport":isport,"host_port":host_port}
                        ports_data.append(dat)
                    #CMD命令
                    cmd_ops = container.attrs['Config']['Cmd']
                    print("CMD命令:",cmd_ops)
                    #Entrypoint
                    entrypoint = container.attrs['Config']['Entrypoint']
                    #环境变量
                    env_ops = container.attrs['Config']['Env']
                    #标签
                    labels_data = []
                    for key,value in container.labels.items():
                        labels_ops = "%s=%s" %(key,value)
                        dat = {"labels_ops":labels_ops}
                        labels_data.append(dat)
                    restart_olicy = container.attrs['HostConfig']['RestartPolicy']['Name']

                    #容器挂载
                    mountss = []
                    if not container.attrs['Mounts']:
                        mounts_Source = "None"
                        mounts_Destination = "None"
                    else:
                        for mounts in container.attrs['Mounts']:
                            mounts_Source = mounts['Source']
                            mounts_Destination = mounts['Destination']
                            dat = {"mounts_Source":mounts_Source,"mounts_Destination":mounts_Destination}
                            mountss.append(dat)
                    
                    #容器网络
                    networks = []
                    network_settings = container.attrs['NetworkSettings']['Networks']
                    for net_name, net_info in network_settings.items():
                        ip_address = net_info['IPAddress']
                        gateway = net_info['Gateway']
                        mac_address = net_info['MacAddress']
                        dat = {"net_name":net_name,"ip_address":ip_address,"gateway":gateway,"mac_address":mac_address}
                        networks.append(dat)

                    #当前容器资源占用情况
                    stats = container.stats(stream=False)
                    #cpu_percent = stats['cpu_stats']['cpu_usage']['total_usage'] / stats['cpu_stats']['system_cpu_usage'] * 100
                    if 'cpu_stats' in stats and 'cpu_usage' in stats['cpu_stats']:
                        total_usage = stats['cpu_stats']['cpu_usage']['total_usage']
                        system_cpu_usage = stats['cpu_stats'].get('system_cpu_usage', 0)

                        if system_cpu_usage != 0:
                            cpu_percent = total_usage / system_cpu_usage * 100
                        else:
                            cpu_percent = 0
                    else:
                        cpu_percent = 0
                    #mem_usage = stats['memory_stats']['usage']
                    if 'memory_stats' in stats and 'usage' in stats['memory_stats']:
                        mem_usage = stats['memory_stats']['usage']
                    else:
                        mem_usage = 0
                    #mem_limit = stats['memory_stats']['limit']
                    if 'memory_stats' in stats and 'limit' in stats['memory_stats']:
                        mem_limit = stats['memory_stats']['limit']
                    else:
                        mem_limit = 0
                    #mem_percent = mem_usage / mem_limit * 100
                    if mem_limit > 0:
                        mem_percent = mem_usage / mem_limit * 100
                    else:
                        mem_percent = 0
                    cpu_ops = "{:.2f}%".format(cpu_percent)
                    mem_ops = "{:.2f}%".format(mem_percent)
                    print("Container {} CPU使用率: {:.2f}%".format(container.name, cpu_percent))
                    print("Container {} 内存使用率: {:.2f}%".format(container.name, mem_percent))
                    # 获取容器的磁盘使用情况

                    if "storage_stats" in stats and "usage" in stats["storage_stats"]:
                        usage_volumes =docker_mod.convert_bytes(stats["storage_stats"]["usage"])
                    else:
                        usage_volumes = "None"
                        print("- 未使用磁盘")
                    
                    # 获取容器的网络统计信息
                    if "networks" in stats:
                        networks_stats = stats["networks"]
                        for network_name, network_stat in networks_stats.items():
                            # 输出网络名称
                            print("- 网络名称: {}".format(network_name))
                                        
                            # 输出网络的流量和包数
                            rx_bytes = network_stat.get("rx_bytes", 0)
                            tx_bytes = network_stat.get("tx_bytes", 0)
                            rx_packets = network_stat.get("rx_packets", 0)
                            tx_packets = network_stat.get("tx_packets", 0)
                            rx_bytes_str = docker_mod.convert_bytes(rx_bytes)
                            tx_bytes_str = docker_mod.convert_bytes(tx_bytes)
                            rx_tx_bytes = "%s/%s" %(rx_bytes_str,tx_bytes_str)  #统计为总数，并非实时网络
                            print("  - 流入字节数: {}".format(rx_bytes))
                            print("  - 流出字节数: {}".format(tx_bytes))
                            print("  - 流入包数: {}".format(rx_packets))
                            print("  - 流出包数: {}".format(tx_packets))
                    else:
                        rx_tx_bytes = "N/A"
                        print("- 未连接到网络")

                    # 更新连接字典
                    connect["rx_tx_bytes"] = rx_tx_bytes

                    
                    if container.status == 'running':
                        cmd = 'ifconfig eth0 | grep "RX packets\|RX bytes\|TX packets\|TX bytes" | awk \'{print $1 ": " $5}\''
                        result = container.exec_run(cmd)
                        output = result.output.decode('utf-8')
                        lines = output.strip().split('\n')
                        rx_packets = tx_packets = rx_bytes = tx_bytes = 0
                        for line in lines:
                            if 'RX packets' in line:
                                rx_packets = int(line.split(':')[1].strip())
                            elif 'TX packets' in line:
                                tx_packets = int(line.split(':')[1].strip())
                            elif 'RX bytes' in line:
                                rx_bytes = int(line.split(':')[1].strip())
                            elif 'TX bytes' in line:
                                tx_bytes = int(line.split(':')[1].strip())
                        print(f'rx_packets={rx_packets}, tx_packets={tx_packets}, rx_bytes={rx_bytes}, tx_bytes={tx_bytes}')
                        # 处理命令执行结果
                    else:
                        # 容器未运行的处理逻辑
                        print("容器未运行，无法执行命令")
        else:
            print("无法连接到Docker守护进程。")
    except docker.errors.DockerException as e:
        # 处理连接异常，你可以根据需要添加相关逻辑
        print("连接 Docker 服务器失败:", e)
        # 返回相关错误信息或页面
        return HttpResponse("连接 Docker 服务器失败")
    except Exception as e:
        print(e)
        traceback.print_exc()
        print("详细错误:", e)
        return JsonResponse({"status": 500, 'msg': '出现未知错误，请登录排查日志信息，或者联系管理员。'})  # 返回错误的响应或适当的处理
    connect = {"id":id,"name":name,"isrunning":isrunning,"status":status,"create_time":create_time,"start_time":start_time,"system_time":system_time,"image":image,
               "ports_data":ports_data,"cmd_ops":cmd_ops,"entrypoint":entrypoint,"env_ops":env_ops,"labels_data":labels_data,"restart_olicy":restart_olicy,
               "mountss":mountss,"networks":networks,
               "cpu_ops":cpu_ops,"mem_ops":mem_ops,"rx_tx_bytes":rx_tx_bytes,"usage_volumes":usage_volumes}
    return render(request, 'container/docker_container_info.html',{"connect":connect})

@csrf_exempt
@login_required
def docker_container_create(request):
    return render(request, 'container/docker_container_create.html')            

# 容器启动方法
@csrf_exempt
@login_required
def docker_container_start_api(request):
    name = request.GET.get("name")
    print("容器名称:",name)
    try:
        success, client = docker_mod.connect_to_docker()
        if success:
            containers = client.containers.list(all=True)
            for container in containers:
                if name == container.name:
                    if container.status == "running":
                        code1 = 1
                        msg_code1 = "容器运行中，无需启动!!!"
                    else:
                        con_restart = client.containers.get(name)
                        con_restart.restart()
                        code1 = 0
                        msg_code2 = "启动容器成功"
        code =code1
        msg = msg_code2
    except Exception as e:
        code =code1
        msg = msg_code1
    result = {'code': code, 'msg': msg}
    return JsonResponse(result)

# 容器重启方法
@csrf_exempt
@login_required
def docker_container_restart_api(request):
    name = request.GET.get("name")
    print("容器名称:",name)
    try:
        success, client = docker_mod.connect_to_docker()
        if success:
            containers = client.containers.list(all=True)
            for container in containers:
                if name == container.name:
                    con_restart = client.containers.get(name)
                    con_restart.restart()     
        code = 0
        msg = "重启%s成功,请刷新查看" %name
    except Exception as e:
        code =1
        msg = "重启%s失败" %name
    result = {'code': code, 'msg': msg}
    return JsonResponse(result)

# 容器停止方法
@csrf_exempt
@login_required
def docker_container_stop_api(request):
    name = request.GET.get("name")
    print("容器名称:",name)
    try:
        success, client = docker_mod.connect_to_docker()
        if success:
            containers = client.containers.list(all=True)
            for container in containers:
                if name == container.name:
                    if container.status == "running":
                        con_restart = client.containers.get(name)
                        con_restart.stop()
                        code1 = 0
                        msg_code1 = "容器已停止"
                    else:
                        code1 = 1
                        msg_code2 = "容器无需停止"
        code =code1
        msg = msg_code2
    except Exception as e:
        code =code1
        msg = msg_code1
    result = {'code': code, 'msg': msg}
    return JsonResponse(result)

# 容器删除方法
@csrf_exempt
@login_required
def docker_container_delete_api(request):
    name = request.GET.get("name")
    print("容器名称:",name)
    try:
        success, client = docker_mod.connect_to_docker()
        if success:
            containers = client.containers.list(all=True)
            for container in containers:
                if name == container.name:
                    if container.status == "running":
                        code1 = 1
                        msg = "您无法删除正在运行的容器,在删除之前请先停止容器!!!"
                    else:
                        try:
                            con_restart = client.containers.get(name)
                            con_restart.remove(force=True)  
                            code1 = 0
                            msg = "容器已删除"
                        except Exception as e:
                            code1 = -1  
                            msg = str(e)  
        code =code1
        msg = msg
    except Exception as e:
        code =code1
        msg = msg
    result = {'code': code, 'msg': msg}
    return JsonResponse(result)

# 容器重命名接口
@csrf_exempt
@login_required
def docker_container_rename_api(request):
    search_key = request.GET.get("search_key")
    name = request.GET.get("name")
    container_id = request.GET.get("id")
    print("容器名称:",name)
    try:
        success, client = docker_mod.connect_to_docker()
        if success:
            containers = client.containers.list(all=True)
            for container in containers:
                if name == container.name:
                    code1 = 1
                    msg_code = "名称已存在"
                    break
            else:
                code1 = 0
                msg_code = "重命名成功"
                # 重命名容器
                container1 = client.containers.get(container_id)
                container1.rename(name)
        code = code1
        msg = msg_code
    except Exception as e:
        code = code1
        msg = msg_code
        print("报错信息:",e)
    result = {'code': code, 'msg': msg}
    return JsonResponse(result)

# 容器更新重启策略接口
@csrf_exempt
@login_required
def docker_container_restart_policy_api(request):
    # 接收前端POST传递的参数
    request_data = QueryDict(request.body)
    container_id = request_data.get("container_id")
    restart_policy = request_data.get("restart_policy")
    try:
        success, client = docker_mod.connect_to_docker()
        if success:
            containers = client.containers.list(all=True)
            # 直接使用传入的重启策略字符串来更新容器配置
            for container in containers:
                if container_id == container.short_id:
                    container.update(restart_policy={"Name": restart_policy})
                    code = 0
                    msg = f"容器 {container_id} 重启策略更新为 {restart_policy} 成功，请刷新查看"
    except Exception as e:
        print("错误信息:",e)
        code =1
        msg = f"容器 {container_id} 重启策略更新失败，错误：{str(e)}"
    result = {'code': code, 'msg': msg}
    return JsonResponse(result)

# 批量重启方法
@csrf_exempt
@login_required
def docker_container_batchrestart_api(request):
    if request.method == "BATCHRESTART":
        # 接收前端POST传递的参数
        request_data = json.loads(request.body.decode('utf-8'))
        results = {}
        try:
            success, client = docker_mod.connect_to_docker()
            if success:
                containers = client.containers.list(all=True)
                # 创建线程池
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    for container_id in request_data:
                        container_id = container_id['id']
                        for container in containers:
                            if container_id == container.short_id:
                                container_name = container.name
                                con_restart = client.containers.get(container_id)
                                future = executor.submit(con_restart.restart, timeout=30)
                                results[container_name] = future
                    # 等待所有任务完成，并收集结果
                    for container_name, future in results.items():
                        try:
                            future.result()  # 如果重启成功，这里不会抛出异常
                            logger.info(f"容器 【 {container_name} 】 重启成功")
                        except Exception as e:
                            logger.error(f"容器 【 {container_name} 】 重启失败：{str(e)}")
                code = 0
                msg = "重启完成"
            else:
                code = 1
                msg = "连接Docker失败"
        except Exception as e:
            logger.error(f"批量重启容器时发生错误：{str(e)}")
            code = 1
            msg = f"容器重启失败，错误：{str(e)}"
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)



@xframe_options_exempt
@login_required
def docker_logs(request):
    name = request.GET.get("name")
    container_id = request.GET.get("container_id")
    containers = request.GET.get("containers")
    connect={"name":name,"container_id":container_id,"containers":containers}
    print("获取到的信息:",connect)
    return render(request, 'container/docker_logs.html',{"connect":connect})

# 终端模块
@xframe_options_exempt
@login_required
def docker_terminal(request):
    name = request.GET.get("name")
    container_id = request.GET.get("container_id")
    containers = request.GET.get("containers")
    connect={"name":name,"container_id":container_id,"containers":containers}
    return render(request, 'container/docker_terminal.html',{"connect":connect})

# 镜像管理
@login_required
def docker_image_info(request):
    return render(request, 'images/docker_images_list.html')

@csrf_exempt
@login_required
def docker_images_api(request):
    if request.method == "GET":
        data = []
        search_key = request.GET.get("search_key")
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                images = client.images.list()
                containers = client.containers.list(all=True)
                for image in images:
                    image_id = image.id
                    image_tag = image.tags
                    # 获取镜像大小（以字节为单位），并将其转换为最接近的二进制单位
                    image_size = humanize.naturalsize(image.attrs['Size'], binary=True)
                    # 获取镜像创建时间
                    time_str = image.attrs['Created']
                    #python 3.7的datetime.strptime方法不支持直接解析纳秒部分
                    #您可以使用第三方库 dateutil 中的 parse 方法解析ISO 8601格式的时间戳，它可以处理各种不同的时间格式,如：时间戳格式为ISO 8601格式，包含纳秒部分
                    time_obj = parser.isoparse(time_str)
                    image_create_time = time_obj.strftime('%Y-%m-%d %H:%M:%S')
                    # 初始设置镜像未被占用
                    image_in_use = any(image_id == container.image.id for container in containers)
                    # 此处循环便利tag是为了解决同一镜像打了不同的tag的情况本质上是同一个镜像，但是tag不一样
                    for tag in image_tag:

                        dat = {"image_id":image_id,"image_tag":tag,"image_size":image_size,"image_create_time":image_create_time,"image_in_use":image_in_use}
                        # 根据查询关键字返回数据
                        if search_key:
                            # any 使用模糊匹配搜索, in 使用完全匹配搜索
                            if any(search_key.lower() in tag.lower() for tag in image_tag):
                                data.append(dat)
                        else:
                            data.append(dat)
                
            code = 0
            msg = "查询成功."
        except Exception as e:
            print(e)
            code = 1
            msg = "查询失败."
        # 分页
        count = len(data)  # 要在切片之前获取总数

        if request.GET.get('page'):  # 如果为真说明数据表格带有分页（适配首页命名空间选择）
            page = int(request.GET.get('page'))
            limit = int(request.GET.get('limit'))
            # data = data[0:10]
            start = (page - 1) * limit  # 切片的起始值
            end = page * limit  # 切片的末值
            data = data[start:end]  # 返回指定数据范围

        result = {'code': code, 'msg': msg, 'data': data, 'count': count}
        return JsonResponse(result)
    elif request.method == "DELETE":
        image_id = request.GET.get("image_id")
        search_key = request.GET.get("search_key")
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                images = client.images.list()
                containers = client.containers.list(all=True)
                #检查是否有运行中的容器使用该镜像，如有停止删除，但是无法检测停止状态的容器
                for container in containers:
                    container_image_id = container.image.id
                    if container_image_id == image_id:
                        code1 = 1
                        code_msg = f"删除失败,请确认镜像是否有容器占用"
                        break
                else:
                    client.images.remove(image_id)
                    code1 = 0
                    code_msg = f"镜像删除成功"
            code = code1
            msg = code_msg
        except DockerException as e:
            logger.error(e)
            code = 2
            if e.status_code == 409 and "image has dependent child images" in str(e):
                msg = "删除失败：存在依赖的子镜像。"
            elif e.status_code == 409 and "image is referenced in multiple repositories" in str(e):
                msg = "删除失败：存在依赖的多个子镜像。"
            else:
                msg = "删除报错：%s" % e
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)
    elif request.method == "FORCEDELETE":
        image_id = request.GET.get("image_id")
        search_key = request.GET.get("search_key")
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                images = client.images.list()
                containers = client.containers.list(all=True)
                #检查是否有运行中的容器使用该镜像，如有停止删除，但是无法检测停止状态的容器
                for container in containers:
                    container_image_id = container.image.id
                    if container_image_id == image_id:
                        code1 = 1
                        code_msg = f"删除失败,请确认镜像是否有容器占用"
                        break
                else:
                    client.images.remove(image_id,force=True)
                    code1 = 0
                    code_msg = f"镜像删除成功"
            code = code1
            msg = code_msg
        except DockerException as e:
            logger.error(e)
            code = 2
            if e.status_code == 409 and "image has dependent child images" in str(e):
                msg = "删除失败：存在多个依赖的子镜像。"
            else:
                msg = "删除报错：%s" % e
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)
    elif request.method == "PULL":
        request_data = QueryDict(request.body)
        image_name = request_data.get('imageUrl')
        registries_url = request_data.get('registriesUrl')
        try:
            # 正则表达式匹配 Docker 镜像地址，包括可选的域名/端口、仓库名和可选的标签
            docker_image_pattern = re.compile(
                r'^(localhost|([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)(:[0-9]+)?)?\/?([a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*(\/[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*)*)(:[\w][\w.-]{0,127})?$'
            )

            # 用正则表达式检查镜像地址格式
            if not docker_image_pattern.match(image_name):
                return JsonResponse({'code': 1, 'msg': '镜像地址格式不正确。'})
            reg = Registries.objects.get(registries_url=registries_url)
            if reg.registries_auth:
                username = reg.registries_username
                # 解密存储的密码
                encrypted_password = reg.registries_password
                key = reg.encryption_key
                # 使用存储的密钥解密密码
                raw_password = docker_mod.decrypt_password(encrypted_password, key)
                # 同步方法
                # 容器管理模块API
                print("接受的镜像仓库:",registries_url,raw_password)
                logger.error(image_name)
                success, client = docker_mod.connect_to_docker()
                if success:
                    # 登录私有镜像仓库
                    login_result = client.login(username, raw_password, registry=registries_url)
                    print("登录结果：", login_result)
                    client.images.pull(image_name)
                    code = 0
                    msg = "镜像拉取成功！"
            else:
                success, client = docker_mod.connect_to_docker()
                if success:
                    client.images.pull(image_name)
                    code = 0
                    msg = "镜像拉取成功！"
        except NotFound:
            logger.error(e)
            code = 1
            msg = f"错误：未能找到或访问私有镜像'{image_name}'。可能是因为权限不足或镜像不存在。"
        except APIError as e:
            logger.error(e)
            code = 1
            if e.status_code == 401 and "unauthorized: authentication required" in str(e):
                msg = f"API错误：未授权失败，无法拉取！"
            else:
                msg = f"API错误：{e.explanation}"
        except ConnectionError:
            logger.error(e)
            code = 1
            msg = "连接错误：无法连接到Docker守护进程。"
        except TimeoutError:
            logger.error(e)
            code = 1
            msg = "超时错误：操作超时。"
        except DockerException as e:
            logger.error(e)
            code = 1
            msg = f"Docker错误：{e}"
        except Exception as e:
            logger.error(e)
            code = 1
            msg = f"未捕获的异常：{e}"

        result = {'code': code, 'msg': msg}
        return JsonResponse(result)
    elif request.method == "CLEAR":
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                # 获取所有镜像
                images = client.images.list(all=True)
                # 遍历镜像列表
                for image in images:
                    print("镜像tag状态:",image.attrs['RepoTags'])
                    if image.attrs['RepoTags'] is None or not image.attrs['RepoTags']:
                        client.images.remove(image.id, force=True)
                        print(f'已删除镜像: {image.id}')
            code = 0
            msg = "清理完成"             
        except DockerException as e:
            logger.error(e)
            code = 1
            if e.status_code == 409 and "image has dependent child images" in str(e):
                msg = "删除失败：存在多个依赖的子镜像。"
            else:
                msg = "删除报错：%s" % e
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)
            

@login_required
def docker_images_pull(request):
    return render(request, 'images/docker_images_pull.html')

# # 回显镜像下拉列表数据
@login_required
def get_images_list(request):
    images_data = []
    try:
        #容器管理模块API
        success, client = docker_mod.connect_to_docker()
        if success:
            images = client.images.list()
            for image in images:
                for tag in image.tags:
                    dat = {
                        "image_tag":tag
                    }
                    images_data.append(dat)
        return JsonResponse({'status': 'success', 'images_data': images_data})
    except DockerException as e:
        logger.error(e)

# 回显镜像仓库下拉列表数据
@login_required
def get_registries_list(request):
    try:
        registries_list = Registries.objects.filter().values('registries_name', 'registries_url')
    except Exception as e:
        logger.error(e)
    return JsonResponse({'status': 'success', 'registries': list(registries_list)})

# 回显网络模式下拉列表数据
@login_required
def get_network_list(request):
    network_data = []
    try:
        #容器管理模块API
        success, client = docker_mod.connect_to_docker()
        if success:
            # 列出所有网络并获取详细信息
            networks = client.networks.list()
            for net in networks:
                network_list = {
                    'driverName':net.attrs.get('Name')
                }
                network_data.append(network_list)
            
        return JsonResponse({'status': 'success', 'network_data': network_data})
    except DockerException as e:
        logger.error(e)
    
# 回显docker卷下拉列表数据
@login_required
def get_volumes_list(request):
    volumes_data = []
    try:
        #容器管理模块API
        success, client = docker_mod.connect_to_docker()
        if success:
            # 列出所有卷并获取详细信息
            volumes = client.volumes.list()
            # 获取所有运行中的容器
            containers = client.containers.list()
            # 创建一个集合来存储当前被使用的卷名
            volumes_in_use = set()
            for container in containers:
                # 检查每个容器的挂载信息
                for mount in container.attrs.get('Mounts', []):
                    # 如果挂载类型是卷，将其名称添加到集合中
                    if mount.get('Type') == 'volume':
                        volumes_in_use.add(mount.get('Name'))
            for vol in volumes:
                vol_in_use = vol.attrs.get("Name") in volumes_in_use
                # 只返回未使用的卷
                if vol_in_use == False:
                    dat = {
                        'name': vol.attrs.get("Name")
                    }
                    volumes_data.append(dat)
            
        return JsonResponse({'status': 'success', 'volumes_data': volumes_data})
    except DockerException as e:
        logger.error(e)


# 网络管理
@login_required
def docker_network_info(request):
    return render(request, 'network/docker_network_list.html')

@csrf_exempt
@login_required
def docker_network_api(request):
    if request.method == "GET":
        data = []
        search_key = request.GET.get("search_key")
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                # 列出所有网络并获取详细信息
                networks = client.networks.list()
                for net in networks:
                    # 提取IPAM配置
                    ipam_config_list = net.attrs.get('IPAM', {}).get('Config', [])
                    if ipam_config_list:  # 确保ipam_config_list不为空
                        ipam_config = ipam_config_list[0]
                        ipv4_subnet = ipam_config.get('Subnet', '')
                        ipv4_gateway = ipam_config.get('Gateway', '')
                    else:
                        ipv4_subnet = '-'
                        ipv4_gateway = '-'
                    net_list = {
                        'name': net.attrs.get('Name'),
                        'driver': net.attrs.get('Driver'),
                        'ipam_driver': net.attrs.get('IPAM', {}).get('Driver'),
                        'ipv4_subnet': ipv4_subnet,
                        'ipv4_gateway': ipv4_gateway,
                    }
                    data.append(net_list)
                code = 0
                msg = "查询成功"
        except DockerException as e:
            logger.error(e)
            code = 1
            msg = "查询失败."
        # 分页
        count = len(data)  # 要在切片之前获取总数

        if request.GET.get('page'):  # 如果为真说明数据表格带有分页（适配首页命名空间选择）
            page = int(request.GET.get('page'))
            limit = int(request.GET.get('limit'))
            # data = data[0:10]
            start = (page - 1) * limit  # 切片的起始值
            end = page * limit  # 切片的末值
            data = data[start:end]  # 返回指定数据范围

        result = {'code': code, 'msg': msg, 'data': data, 'count': count}
        return JsonResponse(result)
    elif request.method == "POST":
        data = []
        network_name = request.POST.get("name", None)
        network_driver = request.POST.get("driver", 'bridge')
        network_ipv4subnet = request.POST.get("ipv4subnet", None)
        network_ipv4gateway = request.POST.get("ipv4gateway", None)
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                # 如果前端未提供driver，则使用默认驱动
                if not network_driver:
                    network_driver = "bridge"  # bridge
                # 创建IPAM配置
                if network_ipv4subnet and network_ipv4gateway:
                    # 验证网关是否在子网内
                    subnet = ipaddress.ip_network(network_ipv4subnet)
                    gateway = ipaddress.ip_address(network_ipv4gateway)
                    if gateway not in subnet:
                        return JsonResponse({
                            'code': 1,
                            'msg': '网关地址不在子网范围内'
                        })

                    ipam_pool = IPAMPool(
                        subnet=network_ipv4subnet,
                        gateway=network_ipv4gateway
                    )
                    ipam_config = IPAMConfig(
                        pool_configs=[ipam_pool]
                    )
                
                client.networks.create(
                    name=network_name,
                    driver=network_driver,
                    ipam=ipam_config
                )
            code = 0
            msg = "提交成功"
        except DockerException as e:
            if e.status_code == 400:
                msg = f"提交包含非法字符，请遵从如下规则[a-zA-Z0-9][a-zA-Z0-9_.-]"
            elif e.status_code == 403:
                msg = f"与现有网段冲突，请更换！！！"
            else:
                msg = f"提交失败{e}"
            logger.error(e)
            code = 1
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)
    elif request.method == "DELETE":
        data = []
        request_data = QueryDict(request.body)
        network_name = request_data.get("name")
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                network = client.networks.get(network_name)
                # 检查是否有容器连接到该网络
                if network.attrs['Containers']:
                    code = 1
                    msg = "网络正在使用中，有连接的容器存在，无法删除。"
                else:
                    # 没有容器，安全删除网络
                    network.remove()
                    code = 0
                    msg = "网络删除成功"
        except DockerException as e:
            logger.error(e)
            code = 1
            msg = "网络正在使用，无法删除."
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)

@login_required
def docker_network_create(request):
    return render(request, 'network/docker_network_create.html')           

@login_required
def docker_network_details(request):
    network_name = request.GET.get("network_name")
    connect = {}
    try:
        #容器管理模块API
        success, client = docker_mod.connect_to_docker()
        if success:
            # 列出所有网络并获取详细信息
            network = client.networks.get(network_name)
            name = network.name
            id = network.id
            scope = network.attrs['Scope']
            driver = network.attrs['Driver']
            ipam_config = network.attrs.get('IPAM', {}).get('Config', [])
            if ipam_config:
                subnet = ipam_config[0].get('Subnet', '-')
                gateway = ipam_config[0].get('Gateway', '-')
            else:
                subnet = '-'
                gateway = '-'

            # 获取连接到指定网络的容器列表
            containers = network.attrs['Containers']
            container_list = []
            for container_id in containers:
                # 获取容器的详细信息
                container = client.containers.get(container_id)
                container_name = container.name
                container_detail = container.attrs['NetworkSettings']['Networks'][network_name]
                container_ipv4address = container_detail['IPAddress']
                container_macaddress = container_detail['MacAddress']
                container_info = {"container_name":container_name,"container_ipv4address":container_ipv4address,"container_macaddress":container_macaddress}
                container_list.append(container_info)

    except docker.errors.DockerException as e:
        # 处理连接异常，你可以根据需要添加相关逻辑
        logger.error(e)
        # 返回相关错误信息或页面
        return HttpResponse("连接 Docker 服务器失败")
    except Exception as ea:
        traceback.print_exc()
        logger.error(ea)
        return JsonResponse({"status": 500, 'msg': '出现未知错误，请登录排查日志信息，或者联系管理员。'})  # 返回错误的响应或适当的处理
    connect = {
        "name":name,
        "id":id,
        "scope":scope,
        "driver":driver,
        "subnet":subnet,
        "gateway":gateway,
        "container_list":container_list

    }
    return render(request, 'network/docker_network_details.html',{"connect":connect})


# 挂载管理
@login_required
def docker_volumes_info(request):
    return render(request, 'volumes/docker_volumes_list.html')

@csrf_exempt
@login_required
def docker_volumes_api(request):
    if request.method == "GET":
        data = []
        search_key = request.GET.get("search_key")
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                # 列出所有卷并获取详细信息
                volumes = client.volumes.list()
                # 获取所有运行中的容器
                containers = client.containers.list()
                # 创建一个集合来存储当前被使用的卷名
                volumes_in_use = set()
                for container in containers:
                    # 检查每个容器的挂载信息
                    for mount in container.attrs.get('Mounts', []):
                        # 如果挂载类型是卷，将其名称添加到集合中
                        if mount.get('Type') == 'volume':
                            volumes_in_use.add(mount.get('Name'))
                
                for vol in volumes:
                    vol_in_use = vol.attrs.get("Name") in volumes_in_use
                    time_str = vol.attrs.get("CreatedAt")
                    time_obj = parser.isoparse(time_str)
                    create_time = time_obj.strftime('%Y-%m-%d %H:%M:%S')
                    dat = {
                        'name': vol.attrs.get("Name"),
                        'driver': vol.attrs.get("Driver"),
                        'mountpoint': vol.attrs.get("Mountpoint"),
                        'createdAt': create_time,
                        'vol_in_use':vol_in_use
                    }
                    data.append(dat)
                code = 0
                msg = "查询成功"
        except DockerException as e:
            logger.error(e)
            code = 1
            msg = "查询失败."
        # 分页
        count = len(data)  # 要在切片之前获取总数

        if request.GET.get('page'):  # 如果为真说明数据表格带有分页（适配首页命名空间选择）
            page = int(request.GET.get('page'))
            limit = int(request.GET.get('limit'))
            # data = data[0:10]
            start = (page - 1) * limit  # 切片的起始值
            end = page * limit  # 切片的末值
            data = data[start:end]  # 返回指定数据范围

        result = {'code': code, 'msg': msg, 'data': data, 'count': count}
        return JsonResponse(result)
    elif request.method == "POST":
        data = []
        volume_name = request.POST.get("name", None)
        volume_driver = request.POST.get("driver", None)
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                # 如果前端未提供name，则使用默认值
                if not volume_name:
                    # 生成一个随机的UUID，然后使用SHA256散列算法
                    random_uuid = uuid.uuid4()
                    volume_name = hashlib.sha256(random_uuid.bytes).hexdigest()

                # 如果前端未提供driver，则使用默认驱动
                if not volume_driver:
                    volume_driver = "local"  # Docker的默认驱动是local
                
                # 提交创建
                client.volumes.create(
                    name=volume_name, 
                    driver=volume_driver
                )
            code = 0
            msg = "提交成功"
        except DockerException as e:
            if e.status_code == 400:
                msg = f"提交包含非法字符，请遵从如下规则[a-zA-Z0-9][a-zA-Z0-9_.-]"
            else:
                msg = f"提交失败{e}"
            logger.error(e)
            code = 1
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)
    elif request.method == "DELETE":
        data = []
        request_data = QueryDict(request.body)
        volume_id = request_data.get("name")
        print("获取ID:",volume_id)
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                volume = client.volumes.get(volume_id)
                volume.remove()
                code = 0
                msg = "卷删除成功"
        except DockerException as e:
            logger.error(e)
            code = 1
            msg = "卷正在使用，无法删除."
        result = {'code': code, 'msg': msg}
        return JsonResponse(result)

@login_required
def docker_volumes_details(request):
    volume_name = request.GET.get("volume_name")
    connect = {}
    try:
        #容器管理模块API
        success, client = docker_mod.connect_to_docker()
        if success:
            # 获取指定卷的详细信息
            volume = client.volumes.get(volume_name)
            ID = volume.id if hasattr(volume, 'id') else volume.name
            CreatedAt = volume.attrs['CreatedAt']
            Mountpoint = volume.attrs['Mountpoint']
            Driver = volume.attrs['Driver']

            # 获取所有容器的信息
            containers = client.containers.list(all=True)  # 包括非运行状态的容器
            # 初始化变量
            ContainerName = '-'
            ContainerID = '-'
            MountPath = '-'
            for container in containers:
                # 检查每个容器的挂载点
                for mount in container.attrs.get('Mounts', []):
                    if mount.get('Type') == 'volume' and mount.get('Name') == volume_name:
                        ContainerName = container.name
                        ContainerID = container.id
                        MountPath = mount.get('Destination')
                    
        else:
            print("无法连接到Docker守护进程。")
    except docker.errors.DockerException as e:
        # 处理连接异常，你可以根据需要添加相关逻辑
        logger.error(e)
        # 返回相关错误信息或页面
        return HttpResponse("连接 Docker 服务器失败")
    except Exception as ea:
        traceback.print_exc()
        logger.error(ea)
        return JsonResponse({"status": 500, 'msg': '出现未知错误，请登录排查日志信息，或者联系管理员。'})  # 返回错误的响应或适当的处理
    connect = {
        'ID':ID,
        'CreatedAt':CreatedAt,
        'Mountpoint':Mountpoint,
        'Driver':Driver,
        'ContainerName':ContainerName,
        'ContainerID':ContainerID,
        'MountPath':MountPath
    }
    return render(request, 'volumes/docker_volemes_details.html',{"connect":connect})

@login_required
def docker_volumes_create(request):
    return render(request, 'volumes/docker_volumes_create.html')

# 事件信息
@login_required
def docker_event_info(request):
    return render(request, 'event/docker_event_list.html')

@login_required
def docker_event_api(request):
    if request.method == "GET":
        data = []
        search_key = request.GET.get("search_key")
        try:
            #容器管理模块API
            success, client = docker_mod.connect_to_docker()
            if success:
                events = client.events()
                # 获取五分钟前的时间和当前时间
                end_time = int(time.time())
                start_time = int((datetime.datetime.now() - datetime.timedelta(minutes=30)).timestamp())
                # 获取最近五分钟内的 Docker 事件
                events = client.events(since=start_time, until=end_time, decode=True)
                for event in events:
                    event_dict = json.loads(json.dumps(event))
                    if event_dict.get('Type') == 'container':
                        id = event_dict['id']
                        container_name = event['Actor']['Attributes']['name']
                        status = event_dict['status']
                        froms = event_dict['from']
                        event_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event_dict.get('time')))
                        dat = {"id":id,"container_name":container_name,"status":status,"froms":froms,"event_time":event_time}
                        data.append(dat)
            events.close()
            code = 0
            msg = "数据获取成功"
        except Exception as e:
            print(e)
            code = 1
            msg = "数据获取失败,报错如下: %s" % e
        # 分页
        count = len(data)  # 要在切片之前获取总数

        if request.GET.get('page'):  # 如果为真说明数据表格带有分页（适配首页命名空间选择）
            page = int(request.GET.get('page'))
            limit = int(request.GET.get('limit'))
            # data = data[0:10]
            start = (page - 1) * limit  # 切片的起始值
            end = page * limit  # 切片的末值
            data = data[start:end]  # 返回指定数据范围

        result = {'code': code, 'msg': msg, 'data': data, 'count': count}
        return JsonResponse(result) 

# 镜像仓库信息
@login_required
def docker_registries_info(request):
    return render(request, 'registries/docker_registries_list.html')

@csrf_exempt
@login_required
def docker_registries_api(request):
    if request.method == "GET":
        data = []
        search_key = request.GET.get("search_key")
        try:
            registries_list = Registries.objects.filter()
            for auth in registries_list:
                registries_name = auth.registries_name
                registries_auth = auth.registries_auth
                registries_url = auth.registries_url
                registries_createdat = docker_mod.timestamp_format(auth.registries_createdat)
                dat = {"registries_name":registries_name,"registries_auth":registries_auth,"registries_url":registries_url,"registries_createdat":registries_createdat}
                if search_key:
                    if search_key in registries_name:
                        data.append(dat)
                else:
                    data.append(dat)
            code = 0
            msg = "查询成功"
        except DockerException as e:
            print(e)
            code = 1
            msg = "数据获取失败,报错如下: %s" % e
        # 分页
        count = len(data)  # 要在切片之前获取总数

        if request.GET.get('page'):  # 如果为真说明数据表格带有分页（适配首页命名空间选择）
            page = int(request.GET.get('page'))
            limit = int(request.GET.get('limit'))
            # data = data[0:10]
            start = (page - 1) * limit  # 切片的起始值
            end = page * limit  # 切片的末值
            data = data[start:end]  # 返回指定数据范围

        result = {'code': code, 'msg': msg, 'data': data, 'count': count}
        return JsonResponse(result)
    elif request.method == "POST":
        name = request.POST.get("name", None)
        url = request.POST.get("url", None)
        auth_enabled = request.POST.get("auth_enabled", "off") == "on"
        username = request.POST.get("username", None)
        password = request.POST.get("password", None)
        try:
            # 尝试通过URL查找现有的仓库
            existing_by_url = Registries.objects.filter(registries_url=url).exists()
            if existing_by_url:
                return JsonResponse({'msg': "新增失败，URL已存在", "code": 1})

            # 尝试通过name查找现有的仓库
            existing_by_name = Registries.objects.filter(registries_name=name).exists()
            if existing_by_name:
                return JsonResponse({'msg': "新增失败，名称已存在", "code": 1})

            if docker_mod.check_docker_connections():
                # 创建新的Registries记录
                Registries.objects.create(
                    registries_name=name,
                    registries_url=url,
                    registries_auth=auth_enabled,
                    registries_username=username if auth_enabled else '',
                    registries_password=password if auth_enabled else ''
                )
                return JsonResponse({'msg': "连接成功，信息已保存", "code": 0})
            else:
                return JsonResponse({'msg': "创建失败，无法连接到Docker", "code": 1})
        except DockerException as e:
            logger.error(e)
            code = 1
            msg = "新增失败,报错如下: %s" % e

        result = {'code': code, 'msg': msg}
        return JsonResponse(result)
    elif request.method == "DELETE":
        request_data = QueryDict(request.body)
        name = request_data.get("registries_name")
        try:
            # 查询用户名是否存在
            Registries.objects.get(registries_name=name)
        except ObjectDoesNotExist:
            code = 1
            msg = "镜像仓库 %s 删除失败" % name
        else:
            Registries.objects.get(registries_name=name).delete()
            code = 0
            msg = "镜像仓库 %s 删除成功" % name
        result = {'msg': msg, "code": code, "username": name}
        return JsonResponse(result)

@login_required
def docker_registries_create(request):
    return render(request, 'registries/docker_registries_create.html')


# 主机列表方法
@login_required
def webssh_info(request):
    return render(request, 'webssh/webssh.html')

@login_required
def webssh_add_info(request):
    return render(request, 'webssh/webssh_add.html')

@csrf_exempt
@xframe_options_exempt
@login_required
def webssh_info_api(request):
    if request.method == "GET":
        data = []
        try:
            host_list = HostMonitoring.objects.filter()
            for auth in host_list:
                host_name = auth.host_name
                host_address = auth.host_address
                dat = {"hostname":host_name,"host_address":host_address}
                data.append(dat)
            code = 0
            msg = "查询成功"
        except DockerException as e:
            print(e)
            code = 1
            msg = "数据获取失败,报错如下: %s" % e
        # 分页
        count = len(data)  # 要在切片之前获取总数

        if request.GET.get('page'):  # 如果为真说明数据表格带有分页（适配首页命名空间选择）
            page = int(request.GET.get('page'))
            limit = int(request.GET.get('limit'))
            # data = data[0:10]
            start = (page - 1) * limit  # 切片的起始值
            end = page * limit  # 切片的末值
            data = data[start:end]  # 返回指定数据范围

        result = {'code': code, 'msg': msg, 'data': data, 'count': count}
        return JsonResponse(result)
    elif request.method == "POST":
        address = request.POST.get("address", None)
        port = request.POST.get("port", None)
        hostname = request.POST.get("hostname", None)
        username = request.POST.get("username", None)
        password = request.POST.get("password", None)
        # 尝试插入数据库之前，检查 host_address 是否唯一
        if HostMonitoring.objects.filter(host_address=address).exists():
            # 如果host_address已存在，返回错误信息
            result = {'msg': f"host_address '{address}' 已存在，不能重复添加。", "code": 1}
        else:
            try:
                # host_address 是唯一的，进行插入操作
                host_create = HostMonitoring(
                    host_name=hostname,
                    host_address=address,
                    host_port=port,
                    host_username=username,
                    host_password=password,
                )
                host_create.save()
                result = {'msg': f"新增 {hostname} 成功", "code": 0}
            except IntegrityError as e:
                # 如果遇到了IntegrityError异常，说明有唯一性约束的违反
                result = {'msg': f"添加失败，违反了唯一性约束: {e}", "code": 1}
            except Exception as e:
                # 处理其他的异常
                result = {'msg': f"新增报错: {e}", "code": 1}

        return JsonResponse(result)
    elif request.method == "DELETE":
        request_data = QueryDict(request.body)
        hostname = request_data.get("hostname")
        try:
            
            host_delete = HostMonitoring.objects.get(host_name=hostname)
        except ObjectDoesNotExist as e:
            code = 1
            msg = "删除报错: %s " % e
        else:
            HostMonitoring.objects.get(host_name=hostname).delete()
            code = 0
            msg = "删除 %s 成功" % hostname
            
        result = {'msg': msg, "code": code}
        return JsonResponse(result)

# 主机终端模块
@xframe_options_exempt
@login_required
def webssh_terminal(request):
    host_address = request.GET.get("host_address")
    print("到了这里:",host_address)
    return render(request, 'webssh/webssh.html',{"host_address":host_address})

# 主机Linux文件系统部分。
@csrf_exempt
@xframe_options_exempt
@login_required
def webssh_file_info(request):
    host_address = request.GET.get("host_address")
    print("主机ID：",host_address)
    return render(request, 'webssh/webssh_file.html',{"host_address":host_address})


# 上传基于SFTP直传--主机列表
@csrf_exempt
@xframe_options_exempt
@login_required
def webssh_update_info(request):
    host_address = request.GET.get("host_address")
    print("文件上传主机ID：",host_address)
    return render(request, 'webssh/webssh_update.html',{"host_address":host_address})

# 上传基于SFTP直传--web终端
@csrf_exempt
@xframe_options_exempt
@login_required
def webssh_upload_terminal_info(request):
    host_address = request.GET.get("host_address")
    remote_path = request.GET.get('selectedFilePath')
    print("文件上传--web终端主机ID:",host_address)
    print("传递的路径地址:",remote_path)
    return render(request, 'webssh/webssh_upload_terminal.html',{"host_address":host_address,"remote_path":remote_path})


# 数据暂存做整合返回前端
uid_cache = {}

# 获取所属用户
def get_owner_name(ssh, uid):
    if uid in uid_cache:
        return uid_cache[uid]
    stdin, stdout, stderr = ssh.exec_command("id -nu " + str(uid))
    owner = stdout.read().decode().strip()

    # Cache the result
    uid_cache[uid] = owner
    return owner

# 文件列表方法
@csrf_exempt
@xframe_options_exempt
@login_required
def webssh_get_directory_list(request):
     # 判断请求类型
    if request.method == "GET":
        host_address = request.GET.get("host_address")
        # 获取路径参数
        path = request.GET.get('path', '/')

        # 获取SSH连接
        transport = host_mod.ssh_manager.get_connection(host_address)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh._transport = transport

        sftp = ssh.open_sftp()

        # 判断路径是否存在
        try:
            sftp.stat(path)
        except FileNotFoundError:
            print('The path does not exist')
            return JsonResponse({'code': 404, 'error': 'The path does not exist.'}, status=404)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            files = [ host_mod.fetch_file_info(executor, ssh, path, fileattr) for fileattr in sftp.listdir_attr(path)]
        # After this line you have list of uids
        uids = {file["owner_future"] for file in files}

        stdin, stdout, stderr = ssh.exec_command("cat /etc/passwd")
        output = stdout.read().decode()
        for line in output.split("\n"):
            try:
                user_name, _, uid, *_ = line.split(":")
                uid = int(uid)
                uid_cache[uid] = user_name
            except ValueError:
                continue
        
        for file in files:
            file["owner"] = uid_cache.get(file.pop('owner_future'), 'Unknown')  # read from cache
        # 对文件进行排序，文件夹在前
        files = sorted(files, key=lambda x: (not x['isFolder'], x['name']))
        # 将结果生成为JsonResponse对象并返回
        return JsonResponse({'code': 200, 'msg': '获取文件列表成功。', 'data': {'path': path, 'files': files}}, safe=False)
        sftp.close()
        ssh.close()
    return JsonResponse({'code': 400, 'error': 'Invalid request.'}, status=400)

@csrf_exempt
@xframe_options_exempt
@login_required
def webssh_update_file_api(request):
    if request.method == "POST":
        host_address = request.GET.get('host_address')
        remote_path = request.POST.get('remote_path')
        file = request.FILES.get('file')
        print("主机ID:",host_address,"上传路径:",remote_path,"文件:",file)

        # 允许上传的文件格式
        allowed_types = [
            'application/octet-stream',
            'application/zip',
            'application/x-gzip',
            'application/x-zip-compressed',
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/x-icon',
            'text/x-sh',
        ]

        # 如果想不限制文件的上传类型，可以去掉这个判断即可
        if file.content_type in allowed_types:
            # 文件在内存中，将其内容写入临时文件
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(file.read())
                file_path = temp_file.name
            
            print("文件临时路径:",file_path)
            try:
                # 获取SSH连接连接池
                transport = host_mod.ssh_manager.get_connection(host_address)
                try:
                    # 建立SSH连接
                    sftp = paramiko.SFTPClient.from_transport(transport)
                    sftp.put(file_path, remote_path + '/' + file.name)
                    os.unlink(file_path)
                    sftp.close()
                    return JsonResponse({'success': True, 'message': '文件上传成功'})
                except HostMonitoring.DoesNotExist:
                    return JsonResponse({'success': False, 'message': '无效的主机ID'})
                except Exception as e:
                    return JsonResponse({'success': False, 'message': '上传失败'})
            except Exception as e:
                return JsonResponse({'success': False, 'message': '数据库连接异常'})
        else:
            print("上传失败,文件类型可能不在上传名单中",file.content_type)
            return JsonResponse({'success': False, 'message': '无效的文件类型'})
    else:
        return JsonResponse({'success': False, 'message': '请求方法错误'})

# 基于SFTP下载文件方法--web终端
@csrf_exempt
@xframe_options_exempt
@login_required
def webssh_download_file_api(request):
    if request.method == "GET":
        host_address = request.GET.get('host_address')
        full_path = request.GET.get('fullPath')
        print("主机ID:",host_address,"下载路径:",full_path)

        try:
            transport = host_mod.ssh_manager.get_connection(host_address)
            sftp = paramiko.SFTPClient.from_transport(transport)

            remote_file = sftp.open(full_path, 'rb')
            file_content = remote_file.read()
            remote_file.close()

            response = HttpResponse(file_content, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(full_path)}"'
            response['Content-Length'] = sftp.stat(full_path).st_size  # 设置 'Content-Length'
        except FileNotFoundError:
            response = JsonResponse({'error': 'File not found'})
        finally:
            if sftp:
                sftp.close()
            if transport:
                transport.close()
            return response

# 基于SFTP删除文件方法--web终端
@csrf_exempt
@xframe_options_exempt
@login_required
def webssh_delete_file_api(request):
    if request.method == 'POST':
        selected_file_path = request.POST.get('selectedFilePath')
        file_name = request.POST.get('fileName')
        host_address = request.POST.get('host_address')
        print("主机ID:",host_address,"删除文件:",file_name)

        try:
            # 连接到 SFTP 主机
            transport = host_mod.ssh_manager.get_connection(host_address)
            sftp = paramiko.SFTPClient.from_transport(transport)
            # 删除文件调用方法
            # sftp_client.remove(selected_file_path + '/' + file_name)
            host_mod.delete_file_or_folder(sftp, selected_file_path + '/' + file_name)
            code = 0
            msg = "文件 %s 删除成功" % file_name
            result = {'msg': msg, "code": code}
            return JsonResponse(result)
        except FileNotFoundError:
            code = 1
            msg = "文件 %s 删除失败" % file_name
            result = {'msg': msg, "code": code}
            return JsonResponse(result)
        finally:
            sftp.close()