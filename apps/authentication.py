# authentication.py
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from .models import CustomUser

# 自定义authenticate方法，用于username与email共同用于账户登录
class CustomUserBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(Q(email=username) | Q(username=username))
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            return None
