# django-jwt-header-auth

A lightweight Django authentication backend for JWT tokens passed by a trusted reverse proxy (like OAuth2-Proxy).

If your setup looks like **Identity Provider → OAuth2-Proxy → Django**, this package handles the Django side: it reads the JWT from the `Authorization` header, creates or updates the user, syncs groups, and gets out of the way.

## How it works

The proxy authenticates users and forwards a JWT in the request header. This package:

1. Decodes the JWT (no signature check — the proxy already did that)
2. Finds or creates a Django user from the token claims (`upn`, `username`, `preferred_username`, or `sub`)
3. Keeps the user's name and group memberships in sync

## Installation

```bash
pip install django-jwt-header-auth
```

Add to your Django settings:

```python
INSTALLED_APPS = [
    # ...
    "jwt_auth",
]

AUTHENTICATION_BACKENDS = [
    "jwt_auth.backends.JWTHeaderBackend",
]

MIDDLEWARE = [
    # ... other middleware ...
    "jwt_auth.middleware.JWTAuthenticationMiddleware",
]
```

## Settings

| Setting | Description |
|---------|-------------|
| `JWT_AUTH_DEFAULT_TOKEN` | A fallback JWT token used when `DEBUG = True` and no `Authorization` header is present. Handy for local development. |

## Expected JWT claims

| Claim | Usage |
|-------|-------|
| `upn` / `username` / `preferred_username` / `sub` | User identity (checked in this order) |
| `name` | Display name |
| `groups` | List of group identifiers — synced to Django groups |

## Requirements

- Python 3.14+
- Django 5.2+
- PyJWT 2.10+
