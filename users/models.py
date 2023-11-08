from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    UserManager,
    PermissionsMixin,
    BaseUserManager,
)
from django.contrib.auth.hashers import make_password

# Create your models here.


class UserManager(BaseUserManager):
    def create_user(self, email, username, password):
        if not email:
            raise ValueError("An email is required")
        if not username:
            raise ValueError("An username is required")
        if not password:
            raise ValueError("A password is required")

        email = self.normalize_email(email)
        user = self.model(email=email, username=username)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, username, password):
        user = self.create_user(email, username, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=128, unique=True)
    username = models.CharField(max_length=32, unique=True)
    is_staff = models.BooleanField(null=False, default=False)
    is_active = models.BooleanField(null=False, default=True)
    is_superuser = models.BooleanField(null=False, default=False)
    last_login = models.DateTimeField(null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        db_table = "user"

    def __str__(self):
        return f"id: {self.id}, username: {self.username}, email: {self.email}"
