import requests
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import authenticate,get_user_model,tokens
from django.conf import settings
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from axes.handlers.proxy import AxesProxyHandler
from .customJWT import CustomJWT
from .serializer import RegisterSerializer,RequestPasswordResetSerializer,ResetPasswordSerializer
from .models import PasswordReset,ActivationCode
from django.core.mail import send_mail
from .utils.send_code import send_activation_code
from .utils.ratelimit import activation_code_ratelimit
from django.core.cache import cache

User = get_user_model()

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
            
            user = User.objects.get(email=data['email'])  # Get saved user
            
            try:
                existing_codes = ActivationCode.objects.filter(user=user)
                if existing_codes.exists():
                    existing_codes.delete()
                send_activation_code(user)
                activation_status = 'Activation code sent to your email.'
            except Exception as e:
                activation_status = f'Account created but failed to send activation code. Error: {str(e)}'
                
            response = Response(
                {
                    'user name': data['userName'],
                    'email': data['email'],
                    'message': 'Register Success',
                    'activation_status': activation_status
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
                max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),  # making it import from SIMPLE_JWT in settings, and making it 1 minute for test access token
            )

            # Set refresh token
            response.set_cookie(
                key='refresh_token',
                value=str(token),
                httponly=True,
                secure=False,
                samesite='Lax',
                max_age=int(settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds())
            )

            return response
        if AxesProxyHandler.is_locked(request):
            return Response({'detail':'You Locked Please try again in 15 minutes.'},status=status.HTTP_403_FORBIDDEN)

        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutApiView(APIView):
    """POST: Logs user out by blacklisting tokens and removing cookies"""
    permission_classes = []

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

class RequestPasswordResetApiView(APIView):
    serializer_class = RequestPasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.filter(email__iexact=email).first()

        if user:
            # Delete any old reset tokens
            PasswordReset.objects.filter(user=user).delete()

            # Generate token
            token_generator = tokens.PasswordResetTokenGenerator()
            token = token_generator.make_token(user)

            # Save new token
            PasswordReset.objects.create(user=user, token=token)

            # Generate reset URL
            reset_url = f"{settings.PASSWORD_RESET_BASE_URL}/{token}"

            # Compose and send email
            message = f"""Dear {user.username},
            
                        We received a request to reset the password for your account.
                        If you want to reset your password, click the link below (or copy and paste it into your browser):
                        {reset_url}
                        If you did not request this, please ignore this message. Your password will not be changed.
                        """

            send_mail(
                "Reset Your Password",
                message,
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)

        return Response({"error": "User with credentials not found"}, status=status.HTTP_404_NOT_FOUND)

class ResetPasswordApiView(APIView):
    serializer_class = ResetPasswordSerializer
    
    def post(self,request,token):
        try:
            serializer  = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            data= serializer.validated_data
            
            reset_obj = PasswordReset.objects.filter(token=token).first()
            
            if not reset_obj:
                return Response({'error':'Invalid token'}, status=400)
            
            if reset_obj.is_expired():
                reset_obj.delete()
                return Response({'error': 'Token expired'}, status=400)
            
            user = reset_obj.user
            user.set_password(data['new_password'])
            user.save()
                
            reset_obj.delete()
                
            return Response({'success':'Password updated'})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      
class ActivatedUserApiView(APIView):
    def post(self, request): 
        # Check if user is already activated
        if request.user.profile.is_activated:
            return Response({'message': 'Account is already activated'}, status=status.HTTP_200_OK)

        activation_code = request.data.get('activation_code')
        if not activation_code:
            return Response({'message': 'Activation code is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            activation = ActivationCode.objects.get(user=request.user)
        except ActivationCode.DoesNotExist:
            return Response({'message': 'No activation code found for this account'}, status=status.HTTP_400_BAD_REQUEST)

        if activation.code != activation_code:
            # rate limit for activation code
            code_ratelimit = activation_code_ratelimit(request.user)
            if not code_ratelimit:
                return Response({"message":"Too many attempts"},status=status.HTTP_429_TOO_MANY_REQUESTS)
            return Response({'detail': 'Invalid activation code'}, status=status.HTTP_400_BAD_REQUEST)

        if activation.is_expired():
            return Response({'message': 'Activation code has expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        # Success: Activate and delete code
        profile = request.user.profile
        profile.is_activated = True
        profile.save()
        activation.delete()
        cache.delete(f"activation_attempts:{request.user.id}")
        return Response({'message': 'Account activated successfully'}, status=status.HTTP_200_OK)

class ResendActivationCodeApiView(APIView):
    def post(self,request):
        user = request.user
        
        if user.profile.is_activated:
            return Response({'message': 'Account is already activated'}, status=status.HTTP_400_BAD_REQUEST)
        
        last_code = ActivationCode.objects.filter(user=user).last()
        if last_code and (timezone.now() - last_code.created_at < timedelta(seconds=60)):
            return Response({'message': 'Please wait before requesting a new code.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        if send_activation_code(user):
            return Response({'message':'Resend Code Successfully'},status=status.HTTP_200_OK)  
        else:
            return Response({'message': 'Failed to resend activation code'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    

        
        
        
            
    