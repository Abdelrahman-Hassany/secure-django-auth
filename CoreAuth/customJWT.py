from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.core.cache import cache
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, UntypedToken
import time

class CustomJWT:
    """Helper class: Handles token blacklisting using Django cache"""

    @staticmethod
    def is_blacklisted(token_str):
        """Check if token (by jti) is blacklisted in cache"""
        try:
            token = UntypedToken(token_str)  # Decode token without assuming type
            jti = token['jti']               # Get JWT ID
            return cache.get(jti) is not None
        except:
            print("Blacklist check failed:")
            return False

    @staticmethod
    def add_to_blacklist(access_token_str, refresh_token_str):
        """Blacklist access and refresh tokens by saving jti to cache until expiry"""
        try:
            # Blacklist access token
            access = AccessToken(access_token_str)
            access_jti = access['jti']
            access_exp = access['exp']
            access_timeout = access_exp - int(time.time())
            cache.set(access_jti, "blacklisted", timeout=access_timeout)

            # Blacklist refresh token
            refresh = RefreshToken(refresh_token_str)
            refresh_jti = refresh['jti']
            refresh_exp = refresh['exp']
            refresh_timeout = refresh_exp - int(time.time())
            cache.set(refresh_jti, "blacklisted", timeout=refresh_timeout)

            return True
        except Exception as e:
            print("Error blacklisting tokens:", e)
            return False
