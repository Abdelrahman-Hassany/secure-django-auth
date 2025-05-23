# Django JWT Authentication with Cookie-Based Tokens and reCAPTCHA v2

This Django project implements a secure authentication system using `JWT` stored in HTTP-only cookies, including features like token blacklisting, custom authentication backend via email, and Google reCAPTCHA v2 protection for registration.

## Features

- JWT authentication using access & refresh tokens
- Tokens stored in secure HTTP-only cookies
- Redis Cloud for chaching `access_tokens` and `refresh_token`
- CustomJWT for check token and add token to blacklist
- Custom Middleware for Handles JWT access/refresh from cookies, injects auth header, and refreshes if needed.
- Automatic token refresh in middleware
- Token blacklisting on logout
- Custom authentication backend using email
- reCAPTCHA v2 validation during registration
- `IsAuthenticated` protected route for user profile (`/api/me`)
- Clean API responses and DRF-based structure

## Requirements

These are the core packages used:

- `django==5.2.1`
- `djangorestframework==3.16.0`
- `djangorestframework-simplejwt==5.5.0`
- `django-redis==5.4.0`
- `python-dotenv==1.1.0`
- `requests==2.32.3`


> `reCAPTCHA v2` is used via Google’s API, ensure your keys are set in `.env`.

## Setup

### 1. Create and activate a virtual environment

Use your preferred tool. For example, with pipenv:

```bash
pipenv shell
```

### 2. Install dependencies

```bash
pipenv install -r requirements.txt
```

Or manually:

```bash
pipenv install django djangorestframework djangorestframework-simplejwt django-redis python-dotenv requests 
```

## Environment Variables

Create a `.env` file in the root of your project and define the following:

```
SECRET_KEY=your_django_secret_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
REDIS_URL=your url for redis cloud
```

You can load the `.env` file in `settings.py` using `python-dotenv`.

## Running the Project

Apply migrations and run the development server:

```bash
python manage.py migrate
python manage.py runserver
```

## Endpoints Summary

| Endpoint       | Method | Description                          |
|----------------|--------|--------------------------------------|
| `/api/register/` | POST   | Register new user with reCAPTCHA    |
| `/api/login/`    | POST   | Login with email & password         |
| `/api/logout/`   | POST   | Logout and blacklist tokens         |
| `/api/me/`       | GET    | Get logged-in user's profile (auth required) |

## Token Handling

- Tokens are stored in HTTP-only cookies (`access_token`, `refresh_token`)
- Middleware handles auto-refresh on expired access token
- Blacklisted tokens are cached using `django-redis`
- Token `jti` is used to manage blacklisting until expiration

## Notes

- reCAPTCHA v2 is used in the registration process to block bots
- Access token refresh is seamless and secure
- Middleware injects the token into request headers for DRF authentication
- All security best practices are followed (except `secure=False` in dev), u should make secure=True in production

## Project Structure
```
.
├── Authentication/
│   ├── middleware.py       # JWTMiddleware with auto-refresh
│   ├── authbackend.py      # Custom EmailBackend
│   └── ...
├── CoreAuth/
│   ├── api_views.py        # API for Register, Login, Logout, Me
│   ├── views.py            # for render Templates
│   ├── serializer.py       # RegisterSerializer
│   ├── customJWT.py        # Token blacklist logic using cache
│   └── ...
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