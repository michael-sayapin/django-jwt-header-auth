from django.contrib import auth


class JWTAuthenticationMiddleware:
    """
    Middleware to automatically log in a user from a JWT header.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # don't re-authenticate
        if hasattr(request, "user") and request.user.is_authenticated:
            return self.get_response(request)
        user = auth.authenticate(request)
        if user:
            # associate the user with the request
            request.user = user
        return self.get_response(request)
