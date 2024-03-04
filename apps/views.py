import docker
from django.http import HttpResponse,JsonResponse, QueryDict,FileResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login,logout 
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .models import CustomUser,Role
from django.contrib.auth.backends import ModelBackend
from django.db import IntegrityError, transaction
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.clickjacking import xframe_options_exempt
from django.shortcuts import get_object_or_404
from loguru import logger
# Create your views here.

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
            return HttpResponse("用户名或密码错误。")
    else:
        return render(request, 'login.html')

# 登出
def user_logout(request):
    logout(request)
    # 重定向到登录页面，这里使用了Django的默认登录路由
    return redirect('/apps/user_login/')



























