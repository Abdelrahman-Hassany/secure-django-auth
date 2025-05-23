from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

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
