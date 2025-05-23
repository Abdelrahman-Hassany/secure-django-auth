from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from jwt import ExpiredSignatureError, InvalidTokenError
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from CoreAuth.customJWT import CustomJWT

class JWTMiddleware(MiddlewareMixin):
    """Middleware: Handles JWT access/refresh from cookies, injects auth header, and refreshes if needed."""

    def process_request(self, request):
        """Intercept request, validate or refresh JWT from cookies, and attach user if valid"""
        token = request.COOKIES.get("access_token")
        refresh_token = request.COOKIES.get("refresh_token")

        if not token:
            return  # No access token provided, let unauthenticated request pass

        # Reject request if token is blacklisted
        if CustomJWT.is_blacklisted(token):
            return JsonResponse({"detail": "Access token is blacklisted."}, status=401)

        # Inject token into headers for DRF authentication
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        authenticator = JWTAuthentication()

        try:
            # Try authenticating with access token
            user, validated_token = authenticator.authenticate(request)
            request.user = user

        except ExpiredSignatureError:
            # If token expired, try using the refresh token
            if not refresh_token:
                return JsonResponse({"detail": "Access token expired. No refresh token."}, status=401)

            if CustomJWT.is_blacklisted(refresh_token):
                return JsonResponse({"detail": "Refresh token is blacklisted."}, status=401)

            try:
                # Create new access token from refresh token
                new_refresh = RefreshToken(refresh_token)
                new_access = str(new_refresh.access_token)

                # Inject refreshed token into header for retrying authentication
                request.META["HTTP_AUTHORIZATION"] = f"Bearer {new_access}"
                request._refresh_access_token = new_access

                # Re-authenticate with the new access token
                user, validated_token = authenticator.authenticate(request)
                request.user = user

            except Exception:
                return JsonResponse({"detail": "Refresh failed."}, status=401)

        except InvalidTokenError:
            # Invalid token (not expired), reject the request
            return JsonResponse({"detail": "Invalid access token."}, status=401)

    def process_response(self, request, response):
        """If access token was refreshed, update the cookie in the response"""
        if hasattr(request, "_refresh_access_token"):
            response.set_cookie(
                key='access_token',
                value=request._refresh_access_token,
                httponly=True,
                secure=False,      # Should be True in production
                samesite='Lax',
                max_age=3600       # Token lifetime in seconds
            )
        return response
