from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

User = get_user_model()

# Register Validation


def validate_data(data):
    email = data["email"].strip()
    username = data["username"].strip()
    password = data["password"].strip()

    if not email:
        raise ValidationError("An email is needed")

    if not username:
        raise ValidationError("An username is needed")

    if not password:
        raise ValidationError("A password is needed")

    if User.objects.filter(email=email).exists():
        raise ValidationError("This username already exists")

    if User.objects.filter(username=username).exists():
        raise ValidationError("This username already exists")

    if len(password) < 8:
        raise ValidationError("The password must be at least 8 characters long")

    return data


# Login Validations


def validate_email(data):
    email = data["email"].strip()
    if not email:
        raise ValidationError("An email is needed")

    return True


def validate_username(data):
    username = data["username"].strip()
    if not username:
        raise ValidationError("An username is needed")

    return True


def validate_password(data):
    password = data["password"].strip()
    if not password:
        raise ValidationError("A password is needed")

    return True
