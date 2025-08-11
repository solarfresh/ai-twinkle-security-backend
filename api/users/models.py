from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """
    A custom user model that inherits from Django's AbstractUser.

    This model can be extended with custom fields and methods as needed,
    while still using Django's powerful built-in authentication system.
    """
    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
        db_table = 'users_user'
