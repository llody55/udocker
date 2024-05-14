from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path
from udockers.websocket.docker_logs_consumers import DockerLogConsumer
from udockers.websocket.docker_terminal_consumers import ProxyConsumer
from udockers.websocket.webssh_consumers import SSHConsumer

websocket_urlpatterns =[
    re_path(r'^apps/docker_logs/$', DockerLogConsumer.as_asgi(),name='docker_logs'),
    re_path(r'^apps/docker_terminal/$', ProxyConsumer.as_asgi(),name='docker_terminal'),
    re_path(r'^webssh_terminal/$', SSHConsumer.as_asgi(),name='webssh_terminal'),
]
application = ProtocolTypeRouter({
    'websocket': AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})