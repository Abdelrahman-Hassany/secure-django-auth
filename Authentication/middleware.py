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

class JWTMiddleware(MiddlewareMixin):
    """
    Middleware: Intercepts requests to authenticate users using JWT tokens stored in cookies.
    Automatically injects access token into headers, attempts re-authentication using refresh token if needed,
    and refreshes token when expired.
    """

    def process_request(self, request):
        """
        Check access and refresh tokens in cookies, inject them into headers for DRF,
        and attach the authenticated user to the request if valid.
        """
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
            # Inject token into headers for DRF authentication
            request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
            try:
                # Attempt authentication using access token
                auth_result = authenticator.authenticate(request)
                if auth_result is not None:
                    user, validated_token = auth_result
                    request.user = user
                    return
            except (AuthenticationFailed, InvalidToken) as e:
                # Access token invalid or expired — will try refresh token fallback
                pass

        # If refresh token is available and valid (not blacklisted)
        if refresh_token and not CustomJWT.is_blacklisted(refresh_token):
            try:
                # Use refresh token to generate new access token
                new_refresh = RefreshToken(refresh_token)
                new_access = str(new_refresh.access_token)

                # Inject new access token into header and attach to request for later use
                request.META["HTTP_AUTHORIZATION"] = f"Bearer {new_access}"
                request._refresh_access_token = new_access

                # Attempt authentication using new access token
                user, validated_token = authenticator.authenticate(request)
                request.user = user
                return
            except TokenError as e:
                # Refresh token is invalid or expired
                return JsonResponse({"detail": "Session expired. Please log in again."}, status=401)

        # No valid access or refresh token — allow as anonymous or protect using decorators later
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
