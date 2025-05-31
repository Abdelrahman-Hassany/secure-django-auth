from django.urls import path
from .api_views import (
    RegisterApiView, LoginApiView, LogoutApiView, MeView,
    RequestPasswordResetApiView, ResetPasswordApiView,
    ActivatedUserApiView, ResendActivationCodeApiView
)

urlpatterns = [
    path('register/', RegisterApiView.as_view(), name='api_register'),
    path('login/', LoginApiView.as_view(), name='api_login'),
    path('logout/', LogoutApiView.as_view(), name='api_logout'),
    path('me/', MeView.as_view(), name='me'),
    path('request-reset-password/', RequestPasswordResetApiView.as_view(), name='api_request_reset_password'),
    path('reset-password/<str:token>/', ResetPasswordApiView.as_view(), name='api_reset_password'),
    path('active-account/', ActivatedUserApiView.as_view(), name='api_active_account'),
    path('resend-code/', ResendActivationCodeApiView.as_view(), name='api_resend_activation_code'),
]
