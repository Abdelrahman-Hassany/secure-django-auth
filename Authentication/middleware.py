from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import (
    InvalidToken,
    AuthenticationFailed,
    TokenError
)
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from CoreAuth.customJWT import CustomJWT
from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse
import logging

logger = logging.getLogger(__name__)

class JWTMiddleware(MiddlewareMixin):
    """
    Middleware to authenticate users using JWT tokens stored in cookies and ensure account activation.
    """
    def process_request(self, request):
        excluded_paths = [reverse('api_logout'), reverse('activation-page'),reverse('api_resend_activation_code'),reverse('api_active_account')]

        token = request.COOKIES.get("access_token")
        refresh_token = request.COOKIES.get("refresh_token")
        authenticator = JWTAuthentication()

        # Allow anonymous requests if no tokens are found
        if not token and not refresh_token:
            return

        # Block blacklisted access token
        if token and CustomJWT.is_blacklisted(token):
            return JsonResponse({"detail": "Unauthorized access."}, status=401)

        if token:
            request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
            try:
                user, validated_token = authenticator.authenticate(request)
                request.user = user
                if hasattr(request.user, "profile") and request.user.is_authenticated:
                    if not request.user.profile.is_activated:
                        if not any(request.path.startswith(path) for path in excluded_paths):
                            return redirect('activation-page')
                return
            except (AuthenticationFailed, InvalidToken):
                pass

        # Try refresh token if access token is invalid
        if refresh_token and not CustomJWT.is_blacklisted(refresh_token):
            try:
                new_refresh = RefreshToken(refresh_token)
                new_access = str(new_refresh.access_token)
                request.META["HTTP_AUTHORIZATION"] = f"Bearer {new_access}"
                request._refresh_access_token = new_access
                user, validated_token = authenticator.authenticate(request)
                request.user = user
                if hasattr(request.user, "profile") and request.user.is_authenticated:
                    if not request.user.profile.is_activated:
                        if not any(request.path.startswith(path) for path in excluded_paths):
                            return redirect('activation-page')
                return
            except TokenError:
                # For web requests, redirect to login; for API, return JSON
                if request.is_ajax():
                    return JsonResponse({"detail": "Session expired. Please log in again."}, status=401)
                return redirect('login')

        return
    
    def process_response(self, request, response):
        """
        If access token was refreshed during request processing,
        update it in the user's cookies.
        """
        if hasattr(request, "_refresh_access_token"):
            response.set_cookie(
                key='access_token',
                value=request._refresh_access_token,
                httponly=True,
                secure=False,  # Use True in production with HTTPS
                samesite='Lax',
                max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),    # making it import from SIMPLE_JWT in settings, and making it 1 minute for test access token
                path="/"
            )
        return response
