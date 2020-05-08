from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
import logging


class JunoPassBackend(ModelBackend):
    """
    JunoPass authentication backend
    """

    def authenticate(self, request, identifier=None):
        try:
            if not identifier:
                raise Exception("Identifier is required")

            user, _ = User.objects.get_or_create(
                username=identifier, defaults={"is_active": True})
            return user if self.user_can_authenticate(user) else None
        except Exception as ex:
            logging.error(ex, exc_info=True)
            return None
