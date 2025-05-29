from django.urls import path
from .views import homepage,register,request_reset_password,reset_password
from .api_views import RegisterApiView,LoginApiView,LogoutApiView,MeView,RequestPasswordResetApiView,ResetPasswordApiView

urlpatterns = [
    path('',homepage,name='homepage'),
    path('register/',register,name='register'),
    path('request_reset_password/',request_reset_password,name='request_reset_password'),
    path('reset_password/<str:token>/', reset_password, name='reset_password_form'),
    path('api/register/',RegisterApiView.as_view(),name='api_register'),
    path('api/login/',LoginApiView.as_view(),name='api_login'),
    path('api/logout/',LogoutApiView.as_view(),name='api_logout'),
    path('api/me/', MeView.as_view(), name='me'),
    path('api/request-reset-password/',RequestPasswordResetApiView.as_view(),name='api_request_reset_password'),
    path('api/reset-password/<str:token>/',ResetPasswordApiView.as_view(),name='api_reset_password')
]