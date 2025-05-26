from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from axes.handlers.proxy import AxesProxyHandler
import requests
from .serializer import RegisterSerializer
from .customJWT import CustomJWT

class RegisterApiView(APIView):
    """POST: Handles user registration with optional reCAPTCHA and sets tokens in cookies"""

    def post(self, request):
        if not settings.TESTING:
            # Validate Google reCAPTCHA
            recaptcha_token = request.data.get('g-recaptcha-response')
            recaptcha_secret_key = settings.RECAPTCHA_SECRET_KEY

            recaptcha_post = requests.post(
                'https://www.google.com/recaptcha/api/siteverify',
                data={
                    'secret': recaptcha_secret_key,
                    'response': recaptcha_token,
                }
            )
            recaptcha_response = recaptcha_post.json()

            if not recaptcha_response.get('success'):
                return Response({'error': 'reCAPTCHA verification failed.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.save()
            response = Response(
                {
                    'user name': data['userName'],
                    'email': data['email'],
                    'message': 'Register Success',
                },
                status=status.HTTP_201_CREATED
            )

            # Set access token in HTTP-only cookie
            response.set_cookie(
                key='access_token',
                value=data['access_token'],
                httponly=True,
                secure=False,  # Set to True in production
                samesite='Lax',
                max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),  # making it import from SIMPLE_JWT in settings, and making it 1 minute for test access token
            )

            # Set refresh token in HTTP-only cookie
            response.set_cookie(
                key='refresh_token',
                value=data['refresh_token'],
                httponly=True,
                secure=False,  # Set to True in production
                samesite='Lax',
                max_age=int(settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds())
            )

            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginApiView(APIView):
    """POST: Authenticates user and returns tokens in cookies"""

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Authenticate user using custom backend
        user = authenticate(request=request, email=email, password=password)

        if user is not None:
            token = RefreshToken.for_user(user)

            response = Response({'message': 'Login Success'}, status=status.HTTP_200_OK)

            # Set access token
            response.set_cookie(
                key='access_token',
                value=str(token.access_token),
                httponly=True,
                secure=False,
                samesite='Lax',
                max_age=3600,
            )

            # Set refresh token
            response.set_cookie(
                key='refresh_token',
                value=str(token),
                httponly=True,
                secure=False,
                samesite='Lax',
                max_age=7 * 24 * 60 * 60,
            )

            return response
        if AxesProxyHandler.is_locked(request):
            return Response({'detail':'You Locked Please try again in 15 minutes.'},status=status.HTTP_403_FORBIDDEN)

        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutApiView(APIView):
    """POST: Logs user out by blacklisting tokens and removing cookies"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        access_token = request.COOKIES.get('access_token')
        refresh_token = request.COOKIES.get('refresh_token')

        if not access_token or not refresh_token:
            return Response({'message': 'tokens not found'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check access token validity (not expired or malformed)
            AccessToken(access_token)
        except Exception(ExpiredSignatureError, InvalidTokenError):
            return Response({'detail': 'Access token expired or invalid'}, status=401)

        # Blacklist tokens
        if CustomJWT.add_to_blacklist(access_token, refresh_token):
            response = Response({'detail': 'Logout successful'}, status=status.HTTP_200_OK)
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response

        return Response({'detail': 'Logout failed'}, status=status.HTTP_400_BAD_REQUEST)


class MeView(APIView):
    """GET: Returns current authenticated user's profile info"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
        })
