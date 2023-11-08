from rest_framework.serializers import (
    ModelSerializer,
    Serializer,
    EmailField,
    CharField,
)
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from ..models import User


class UserRegisterSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ("email", "username", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, data):
        user_object = User.objects.create_user(
            email=data["email"],
            username=data["username"],
            password=data["password"],
        )
        user_object.save()
        return user_object


class UserLoginSerializer(Serializer):
    email = EmailField()
    password = CharField(write_only=True)

    def check_user(self, data):
        user = authenticate(username=data["email"], password=data["password"])
        if not user:
            raise ValidationError("User not found")
        return user


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ("email", "username")


class UserLogoutSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ()
