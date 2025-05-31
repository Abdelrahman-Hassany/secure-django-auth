from django.urls import path
from .views import (
    homepage, register, request_reset_password,
    reset_password, activation_page
)

urlpatterns = [
    path('', homepage, name='homepage'),
    path('register/', register, name='register'),
    path('request_reset_password/', request_reset_password, name='request_reset_password'),
    path('reset_password/<str:token>/', reset_password, name='reset_password_form'),
    path('activation-page/', activation_page, name='activation-page'),
]
