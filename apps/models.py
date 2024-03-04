from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

# Create your models here.
# 自定义权限模型
class Permission(models.Model):
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

# 自定义角色模型
class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    permissions = models.ManyToManyField(Permission)

    def __str__(self):
        return self.name

# 自定义用户模型的管理器
class CustomUserManager(BaseUserManager):
    def create_user(self, email,username, password=None, **extra_fields):
        if not email:
            raise ValueError('必须设置一个电子邮件地址')
        if not username:
            raise ValueError('必须设置一个用户名')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email,username, password, **extra_fields):
        """创建并返回一个拥有管理员权限的用户。"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('超级用户必须拥有is_staff=True。')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('超级用户必须拥有is_superuser=True。')

        return self.create_user(email,username, password, **extra_fields)

# 自定义用户模型
class CustomUser(AbstractBaseUser, PermissionsMixin):
    """自定义用户模型，使用电子邮件作为唯一标识符。"""
    email = models.EmailField(unique=True,verbose_name='电子邮件')
    username = models.CharField(max_length=20, unique=True, verbose_name='用户名')
    nickname = models.CharField(max_length=150, null=True, blank=True, verbose_name='用户昵称')
    is_staff = models.BooleanField(default=False,verbose_name='账户状态')
    is_active = models.BooleanField(default=True,verbose_name='激活状态')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='创建时间')
    avatar = models.ImageField(upload_to='images/avatars/%Y/%m',default="images/avatars/default.jpg", null=True, blank=True, verbose_name='头像')  # 设置用户头像存储在images/avatars目录下，按照年%Y月%m区分
    gender = models.CharField(max_length=1, choices=(('M', 'Male'), ('F', 'Female'), ('O', 'Other')), blank=True, verbose_name='性别')
    tags = models.CharField(max_length=100, blank=True, verbose_name='标签')
    roles = models.ManyToManyField(Role)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    # 重写has_perm方法来检查角色权限
    def has_perm(self, perm, obj=None):
        # 是否有特定权限
        if self.is_superuser:  # 超级管理员拥有所有权限
            return True
        if not self.is_active:  # 非活跃用户没有权限
            return False
        # 检查用户角色的权限
        for role in self.roles.all():
            if role.permissions.filter(codename=perm).exists():
                return True
        return False