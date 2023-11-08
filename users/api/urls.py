from django.urls import path
from .views import Register, Login, Logout, UserView, get_routes

urlpatterns = [
    path("", get_routes),
    path("api/", get_routes),
    path("api/userview/", UserView.as_view(), name="userview"),
    path("api/register/", Register.as_view(), name="register"),
    path("api/login/", Login.as_view(), name="login"),
    path("api/logout/", Logout.as_view(), name="logout"),
]
