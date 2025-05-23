from django.urls import path
from .views import homepage,login,register
from .api_views import RegisterApiView,LoginApiView,LogoutApiView,MeView

urlpatterns = [
    path('',homepage,name='homepage'),
    path('login/',login,name='login'),
    path('register/',register,name='register'),
    path('api/register/',RegisterApiView.as_view(),name='api_register'),
    path('api/login/',LoginApiView.as_view(),name='api_login'),
    path('api/logout/',LogoutApiView.as_view(),name='api_logout'),
    path('api/me/', MeView.as_view(), name='me'),
]