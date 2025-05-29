# Secure Django Auth

This project is a secure and extensible Django authentication system built with Django Rest Framework. It includes the following features:

- Custom user model
- Login, logout, registration, and token-based authentication
- Password reset via email
- Rate-limited login and reset password endpoints using Redis
- reCAPTCHA v2 integration
- Secure password validation
- Environment variable management with `.env` file
- SMTP email backend setup with Gmail (for testing)

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/Abdelrahman-Hassany/secure-django-auth.git
cd secure-django-auth
```

### 2. Install Dependencies using Pipenv

```bash
pip install pipenv
pipenv install
pipenv shell
```

### 3. Set Environment Variables

Create a `.env` file in the root directory and add the following:

```
SECRET_KEY=your-django-secret-key

# Google reCAPTCHA v2
RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key

# Redis Cloud URL (for throttling and rate limiting)
REDIS_URL=your-redis-cloud-url

# Gmail SMTP Settings
EMAIL_HOST_USER=your-gmail-address@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Frontend Reset Password Base URL
PASSWORD_RESET_BASE_URL=http://127.0.0.1:8000/reset_password
```

> Note: Using Gmail for sending emails is not suitable for production. It is recommended only for local development or testing purposes. For production, use services like SendGrid, Mailgun, or Amazon SES.

### 4. Apply Migrations

```bash
python manage.py migrate
```

### 5. Run the Server

```bash
python manage.py runserver
```

---

## Password Reset Flow

- User submits their email to `/api/request-reset-password/`
- If email exists, a password reset token is generated and emailed to the user
- The user follows the link to `/reset_password/{token}` (frontend)
- On submitting new password to `/api/reset-password/{token}/`, password is updated

---

## Redis Cloud Setup

Redis is used to store rate limiting data. You can use Redis Cloud:

1. Go to [Redis Cloud](https://app.redislabs.com/)
2. Create a free database
3. Copy the Redis URL in the format:  
   `redis://default:<password>@<host>:<port>`
4. Add it to `.env` under `REDIS_URL`

---

## Google reCAPTCHA v2 Setup

To enable reCAPTCHA v2:

1. Go to [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin/create)
2. Register your site and choose reCAPTCHA v2 ("I'm not a robot" checkbox)
3. Add the **site key** to `.env` as `RECAPTCHA_SECRET_KEY`
4. In the frontend, include the reCAPTCHA script and `g-recaptcha-response` in your form submission

Example frontend snippet:

```html
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<form>
  <!-- your fields -->
  <div class="g-recaptcha" data-sitekey="your-site-key"></div>
  <button type="submit">Submit</button>
</form>
```

In the backend, verify the token with Google reCAPTCHA using `requests.post` to:

```
https://www.google.com/recaptcha/api/siteverify
```

---

## Token Handling

- Tokens are stored in HTTP-only cookies (`access_token`, `refresh_token`)
- Middleware handles auto-refresh on expired access token
- Blacklisted tokens are cached using `django-redis`
- Token `jti` is used to manage blacklisting until expiration

## Security Notes

- reCAPTCHA v2 is used in the registration process to block bots
- Login is rate-limited using `django-axes` to prevent brute-force attacks
- Password validation rules enforced:
  - Minimum 8 characters
  - Not too similar to user attributes
  - Not a common password
  - Not entirely numeric
- Middleware injects the token into request headers for DRF authentication
- All security best practices are followed (except `secure=False` in dev, should be `True` in production)

> Note: You should include the following method in your registration serializer to activate password validation:

```python
def validate_password(self, value):
    validate_password(value)
    return value
```

## Notes

- reCAPTCHA v2 is used in the registration process to block bots
- Access token refresh is seamless and secure
- Middleware injects the token into request headers for DRF authentication

## API Endpoints

| Method | Endpoint                         | Description                          |
|--------|----------------------------------|--------------------------------------|
| POST   | `/api/register/`                 | Register new user using reCAPTCHA    |
| POST   | `/api/login/`                    | Login with email & password          |
| POST   | `/api/logout/`                   | Logout user (invalidate token)       |
| GET    | `/api/me/`                       | Retrieve authenticated user details  |
| POST   | `/api/request-reset-password/`   | Request password reset link          |
| POST   | `/api/reset-password/<token>/`   | Reset password using token           |

---

## Project Structure

```
secure-django-auth/
├── Authentication/           # Custom middleware and JWT tools
├── CoreAuth/                 # Views, serializers, API logic
├── templates/                # HTML frontend templates
├── static/                   # Static files (CSS, JS)
├── manage.py
├── .env
└── README.md
```

## Testing

The project includes automated API tests using Django's `APITestCase`.

To run the tests:

```bash
python manage.py test
```

Tests cover key authentication flows including:

- Successful and failed user registration
- Login and token issuance
- Logout and token blacklisting
- Protected routes access
- Access token refresh through middleware

## Contributions

Feel free to fork the repo and submit a pull request!