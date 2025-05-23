from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

UserModel = get_user_model()

class EmailBackend(ModelBackend):
    """Authentication backend: Allows login using email instead of username."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Authenticate user using email and password"""
        email = kwargs.get('email') or username  # Use 'email' param or fallback to 'username'

        try:
            # Try to fetch user by email
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return None  # No user found with that email

        # Check password and if user is active (via `user_can_authenticate`)
        if user.check_password(password) and self.user_can_authenticate(user):
            return user

        return None  # Incorrect password or inactive user
