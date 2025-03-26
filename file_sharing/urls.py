
from .views import refresh_files
# urls.py
from django.urls import path
from . import views
from .views import register, user_logout,user_login, dashboard, upload_file, download_file
from.views import home_view
from .views import verify_otp
from .views import send_otp,verify_otp

urlpatterns = [
    path('home/',home_view,name='home'),
    path('', user_login, name="login"),
    path('register/', register, name='register'),
    path('login/', user_login, name='login'),
    path('dashboard/', dashboard, name='dashboard'),
    path('upload/', upload_file, name='upload'),
    path('logout/', user_logout, name='user_logout'),
    path('download/<int:file_id>/', download_file, name='download'),
    path('chat/<str:room_name>/', views.chat_room, name='chat'),

    path('refresh-files/', refresh_files, name='refresh_files'),
    path("verify-otp/", verify_otp, name="verify_otp"),
    path("send-otp/", send_otp, name="send_otp"),
   

]
