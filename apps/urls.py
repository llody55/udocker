from django.urls import path,re_path,include
from apps import views

urlpatterns = [
    re_path('user_login/',views.user_login,name="user_login"),
    re_path('logout/',views.user_logout,name="logout"),
    re_path('password_reset_request/',views.password_reset_request,name="password_reset_request"),

    re_path('docker_container/',views.docker_container,name="docker_container"),
    re_path("docker_container_api/",views.docker_container_api,name="docker_container_api"),  # 远程docker容器管理列表
    re_path("docker_container_create/",views.docker_container_create,name="docker_container_create"),

    re_path("docker_container_info/",views.docker_container_info,name="docker_container_info"),  # 远程docker容器管理详情列表
    re_path("docker_container_start_api/",views.docker_container_start_api,name="docker_container_start_api"),  # 远程docker容器管理启动容器
    re_path("docker_container_restart_api/",views.docker_container_restart_api,name="docker_container_restart_api"),  # 远程docker容器管理重启容器
    re_path("docker_container_stop_api/",views.docker_container_stop_api,name="docker_container_stop_api"),  # 远程docker容器管理停止容器
    re_path("docker_container_delete_api/",views.docker_container_delete_api,name="docker_container_delete_api"),  # 远程docker容器管理删除容器
    re_path("docker_container_rename_api/",views.docker_container_rename_api,name="docker_container_rename_api"),  # 远程docker容器名称重命名
    re_path("docker_container_restart_policy_api/",views.docker_container_restart_policy_api,name="docker_container_restart_policy_api"),  # 远程docker容器重启策略更新接口
    re_path("docker_container_batchrestart_api/",views.docker_container_batchrestart_api,name="docker_container_batchrestart_api"),
    re_path("docker_logs/",views.docker_logs,name="docker_logs"),  # 远程docker容器日志
    re_path("docker_terminal/",views.docker_terminal,name="docker_terminal"),  # 远程docker容器终端

    re_path("docker_image_info/",views.docker_image_info,name="docker_image_info"),  # 远程docker镜像管理
    re_path("docker_images_api/",views.docker_images_api,name="docker_images_api"),  # 远程docker镜像管理API
    re_path("docker_images_pull/",views.docker_images_pull,name="docker_images_pull"),  # 远程docker镜像管理拉取镜像
    re_path("docker_rollback_api/",views.docker_rollback_api,name="docker_rollback_api"), 

    re_path("get_images_list/",views.get_images_list,name="get_images_list"),
    re_path("get_registries_list/",views.get_registries_list,name="get_registries_list"),
    re_path("get_volumes_list/",views.get_volumes_list,name="get_volumes_list"),
    re_path("get_network_list/",views.get_network_list,name="get_network_list"),
    re_path("get_historicalmirror_list/",views.get_historicalmirror_list,name="get_historicalmirror_list"),

    re_path("docker_network_info/",views.docker_network_info,name="docker_network_info"),  # 远程docker网络管理页面
    re_path("docker_network_api/",views.docker_network_api,name="docker_network_api"),  # 远程docker网络管理API
    re_path("docker_network_create/",views.docker_network_create,name="docker_network_create"), # 远程docker网络管理创建页
    re_path("docker_network_details/",views.docker_network_details,name="docker_network_details"), # 远程docker网络管理详情页

    re_path("docker_volumes_info/",views.docker_volumes_info,name="docker_volumes_info"),  # 远程docker挂载管理页面
    re_path("docker_volumes_api/",views.docker_volumes_api,name="docker_volumes_api"),  # 远程docker挂载管理API
    re_path("docker_volumes_details/",views.docker_volumes_details,name="docker_volumes_details"), # 远程docker挂载管理详细信息
    re_path("docker_volumes_create/",views.docker_volumes_create,name="docker_volumes_create"), # 远程docker挂载管理创建挂载

    re_path("docker_event_info/",views.docker_event_info,name="docker_event_info"),  # 远程docker事件信息
    re_path("docker_event_api/",views.docker_event_api,name="docker_event_api"),  # 远程docker事件信息API

    re_path("docker_registries_info/",views.docker_registries_info,name="docker_registries_info"), # 镜像仓库页面
    re_path("docker_registries_api/",views.docker_registries_api,name="docker_registries_api"), # 镜像仓库API
    re_path("docker_registries_create/",views.docker_registries_create,name="docker_registries_create"), # 镜像仓库创建页
    re_path("docker_registries_rename_api/",views.docker_registries_rename_api,name="docker_registries_rename_api"), # 备注更新接口

    re_path("webssh_info/",views.webssh_info,name="webssh_info"),  # 主机终端首页
    re_path("webssh_add_info/",views.webssh_add_info,name="webssh_add_info"),
    re_path("webssh_info_api/",views.webssh_info_api,name="webssh_info_api"),
    re_path("webssh_file_info/",views.webssh_file_info,name="webssh_file_info"), 
    re_path("webssh_terminal/",views.webssh_terminal,name="webssh_terminal"),
    re_path("webssh_get_directory_list/",views.webssh_get_directory_list,name="webssh_get_directory_list"),  # 文件列表方法

    re_path("webssh_update_info/",views.webssh_update_info,name="webssh_update_info"),  # 上传新方法
    re_path("webssh_upload_terminal_info/",views.webssh_upload_terminal_info,name="webssh_upload_terminal_info"),  # 终端sftp直传方式
    re_path("webssh_update_file_api/",views.webssh_update_file_api,name="webssh_update_file_api"),  # 上传API
    re_path("webssh_download_file_api/",views.webssh_download_file_api,name="webssh_download_file_api"),  # 下载方法API
    re_path("webssh_delete_file_api/",views.webssh_delete_file_api,name="webssh_delete_file_api"),  # 删除文件方法API

    re_path("about/",views.about,name="about"),
]