from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthTests(APITestCase):

    def setUp(self):
        """Prepare shared test data and URLs"""
        self.register_url = '/api/register/'
        self.login_url = '/api/login/'
        self.logout_url = '/api/logout/'
        self.protected_url = '/api/me/'  

        self.user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "password": "password123",
            "confirm_password": "password123"
        }

    def test_user_registration_success(self):
        """Test: Successful registration"""
        # Arrange + Act
        response = self.client.post(self.register_url, self.user_data, format='json')

        # Assert
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)


    def test_user_registration_password_mismatch(self):
        """Test: Registration fails when passwords do not match"""
        # Arrange
        self.user_data["confirm_password"] = "diffrent passowrd"

        # Act
        response = self.client.post(self.register_url, self.user_data, format='json')

        # Assert
        self.assertEqual(response.status_code, 400)
        self.assertIn("Passwords do not match.", response.data['confirm_password'])

    def test_login_success(self):
        """Test: User can login and receive tokens"""
        # Arrange
        self.client.post(self.register_url, self.user_data, format='json')

        # Act
        response = self.client.post(self.login_url, {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        }, format='json')

        # Assert
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)

    def test_logout_blacklists_tokens(self):
        """Test: Logout invalidates tokens"""
        # Arrange: Register + Login
        self.client.post(self.register_url, self.user_data, format='json')
        login_res = self.client.post(self.login_url, {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        }, format='json')

        access = login_res.cookies.get('access_token').value
        refresh = login_res.cookies.get('refresh_token').value

        # Act: Call logout with cookies set
        self.client.cookies['access_token'] = access
        self.client.cookies['refresh_token'] = refresh
        response = self.client.post(self.logout_url)

        # Assert
        self.assertEqual(response.status_code, 200)

    def test_protected_view_requires_auth(self):
        """Test: Protected view requires valid token"""
        # Arrange: Register + Login
        self.client.post(self.register_url, self.user_data, format='json')
        login_res = self.client.post(self.login_url, {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        }, format='json')
        access = login_res.cookies.get('access_token').value

        # Act: Call protected endpoint with access token
        self.client.cookies['access_token'] = access
        response = self.client.get(self.protected_url)

        # Assert
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["email"], self.user_data["email"])

    def test_access_token_rejected_after_logout(self):
        """Test: Access token no longer works after logout (blacklist)"""
        # Arrange: Register + Login
        self.client.post(self.register_url, self.user_data, format='json')
        login_res = self.client.post(self.login_url, {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        }, format='json')

        access = login_res.cookies.get('access_token').value
        refresh = login_res.cookies.get('refresh_token').value

        # Logout
        self.client.cookies['access_token'] = access
        self.client.cookies['refresh_token'] = refresh
        self.client.post(self.logout_url)

        # Try to access protected view again
        self.client.cookies['access_token'] = access
        response = self.client.get(self.protected_url)

        # Assert
        self.assertEqual(response.status_code, 401)
