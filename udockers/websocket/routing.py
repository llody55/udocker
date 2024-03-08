from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path
from udockers.websocket.docker_logs_consumers import DockerLogConsumer
from udockers.websocket.docker_terminal_consumers import TerminalConsumer

websocket_urlpatterns =[
    re_path(r'^apps/docker_logs/$', DockerLogConsumer.as_asgi(),name='docker_logs'),
]
application = ProtocolTypeRouter({
    'websocket': AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})