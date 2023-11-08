from django.contrib.auth import login, logout
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

from .serializers import (
    UserSerializer,
    UserLoginSerializer,
    UserRegisterSerializer,
    UserLogoutSerializer,
)
from .validators import (
    validate_password,
    validate_email,
    validate_username,
    validate_data,
)

# Create your views here.


@api_view(["GET"])
def get_routes(request):
    path_info = request.META.get("PATH_INFO")
    http_host = request.META.get("HTTP_HOST")
    routes = [
        "http://" + http_host + path_info + "userview/",
        "http://" + http_host + path_info + "register/",
        "http://" + http_host + path_info + "login/",
        "http://" + http_host + path_info + "logout/",
    ]

    return Response(routes)


class UserView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def get(self, request):
        user_serializer = UserSerializer(request.user)
        return Response({"user": user_serializer.data}, status=status.HTTP_200_OK)


class Register(APIView):
    serializer_class = UserRegisterSerializer

    def post(self, request, *args, **kwargs):
        validated_data = validate_data(request.data)
        serializer = UserRegisterSerializer(data=validated_data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.create(validated_data)
            if user:
                return Response(
                    {"User": serializer.data, "Message": "Registration successful"},
                    status=status.HTTP_201_CREATED,
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        assert validate_email(data)
        assert validate_password(data)
        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.check_user(data)
            login(request, user)
            return Response(
                {"User": serializer.data, "Message": "Login successful"},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


"""class Login(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")

        user = None
        if "@" in username:
            try:
                user = User.objects.get(email=username)
            except ObjectDoesNotExist:
                pass

        if not user:
            user = authenticate(username=username, password=password)

        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({"token": token.key}, status=status.HTTP_200_OK)

        return Response(
            {"error": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )


class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        login_serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if login_serializer.is_valid():
            user = login_serializer.validated_data["user"]
            if user.is_active:
                token, created = Token.objects.get_or_create(user=user)
                user_serializer = UserSerializer(user)
                if created:
                    return Response(
                        {
                            "token": token.key,
                            "usuario": user_serializer.data,
                            "mensaje": "Login successful",
                        },
                        status=status.HTTP_201_CREATED,
                    )
                else:
                    token.delete()
                    return Response(
                        {"error": "This user has already logged in"},
                        status=status.HTTP_409_CONFLICT,
                    )
            else:
                return Response(
                    {"error": "This user cannot log in"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        else:
            return Response(login_serializer.errors, status=status.HTTP_400_BAD_REQUEST)"""


class Logout(APIView):
    serializer_class = UserLogoutSerializer

    def post(self, request, *args, **kwargs):
        logout(request)
        return Response({"Message": "Logout successful"}, status=status.HTTP_200_OK)


"""class Logout(APIView):
    def get(self, request, *args, **kwargs):
        token = request.query_params.get("token")
        token = Token.objects.filter(key=token).first()
        print(token)
        if token:
            user = token.user

            all_sessions = Session.objects.filter(expire_date__gte=timezone.now())
            if all_sessions.exists():
                for session in all_sessions:
                    session_data = session.get_decoded()
                    if user.id == session_data.get("_auth_user_id"):
                        session.delete()

            token.delete()

            session_message = "User session deleted"
            token_message = "Token deleted"
            return Response(
                {"token_message": token_message, "session_message": session_message},
                status=status.HTTP_200_OK,
            )

        return Response(
            {"error": "There is no user with these credentials"},
            status=status.HTTP_400_BAD_REQUEST,
        )"""
