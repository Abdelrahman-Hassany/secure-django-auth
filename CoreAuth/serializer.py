from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    """Serializer: Handles user registration, validation, and token return"""

    # Required fields for registration
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
            'email',
            'password',
            'confirm_password'
        ]
    def validate_password(self, value):
        """Validate that password is secure"""
        validate_password(value)
        return value
    
    def validate(self, data):
        """Validate that password and confirm_password match"""
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        """Create new user, hash password, set username, and return tokens"""
        validated_data.pop('confirm_password')               # No need to store confirmation field
        password = validated_data.pop('password')            # Extract raw password

        # Format username as "First Last"
        first_name = validated_data.get('first_name')
        last_name = validated_data.get('last_name')

        user = User(**validated_data)
        user.set_password(password)
        user.username = f"{first_name.strip().title()} {last_name.strip().title()}"
        user.save()

        # Generate JWT tokens for the new user
        refresh = RefreshToken.for_user(user)

        return {
            'userName': user.username,
            'email': user.email,
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        }

class RequestPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        if not User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("No user is associated with this email address.")
        return value
    
class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.RegexField(
        regex=r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
        write_only=True,
        error_messages={'invalid': ('Password must be at least 8 characters long with at least one capital letter and symbol')})
    confirm_password = serializers.CharField(write_only=True, required=True)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data
    