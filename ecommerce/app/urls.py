from django.urls import path
from . import views
from . authviews import register,verify_email,login,logout,delete_user

urlpatterns = [
    path('slider/',views.slider,name='slider'),
    path('register/', register, name='register'),
    path('verify-email/', verify_email, name='verify-email'),
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),
    path('delete_user/', delete_user, name='delete_user'),
] 

