import hashlib
import logging

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import Group
from django.core.cache import cache

User = get_user_model()


logger = logging.getLogger(__name__)


class JWTHeaderBackend(BaseBackend):
    """
    Authenticates a user via a JWT in a request header set by a trusted proxy.
    Creates and updates users on-the-fly based on the 'upn' claim.
    """

    def authenticate(self, request):
        token_header = request.META.get("HTTP_AUTHORIZATION")

        if not token_header:
            if settings.DEBUG:
                token_header = getattr(settings, "JWT_AUTH_DEFAULT_TOKEN", None)
            else:
                return None

        if not token_header:
            return None

        token_header = token_header.strip().split(" ")[-1]

        try:
            # oauth2-proxy has already verified the token signature
            # we just need to decode it to get the claims
            payload = jwt.decode(token_header, options={"verify_signature": False})
        except jwt.PyJWTError as e:
            logger.error("error decoding JWT", extra={"error": str(e)})
            return None

        upn = (
            payload.get("upn")
            or payload.get("username")
            or payload.get("preferred_username")
            or payload.get("sub")
        )
        if not upn:
            logger.error("no upn found in JWT", extra={"payload": payload})
            return None

        # NB: yes, the following happens every every request,
        # but it's a cheap lookup and we don't need to cache the user

        user, _ = User.objects.get_or_create(
            username=upn, defaults={"name": payload.get("name")}
        )
        if user.name != payload.get("name"):
            user.name = payload.get("name")
            user.save(update_fields=["name"])
        # FIXME: switch this to a group membership check
        if "_adm@" in upn and not user.is_superuser:
            user.is_staff = True
            user.is_superuser = True
            user.save(update_fields=["is_staff", "is_superuser"])

        groups = []
        if group_uuids := payload.get("groups", []):
            group_uuids.sort()
            group_uuids_hash = hashlib.sha256(repr(group_uuids).encode()).hexdigest()
            group_uuids_hash_cache = cache.get(f"group_uuids_hash_{user.id}")
            if group_uuids_hash_cache != group_uuids_hash:
                groups = Group.objects.bulk_create(
                    [Group(name=group) for group in group_uuids],
                    update_conflicts=True,
                    unique_fields=["name"],
                    update_fields=["name"],
                )
                user.groups.set(groups)
                cache.set(
                    f"group_uuids_hash_{user.id}",
                    group_uuids_hash,
                    timeout=60 * 60 * 24,
                )

        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
