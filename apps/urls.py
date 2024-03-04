from django.urls import path,re_path,include
from apps import views

urlpatterns = [
    re_path('index',views.index,name="index"),
    re_path('user_login/',views.user_login,name="user_login"),
    re_path('logout/',views.user_logout,name="logout"),
]