# main_app/urls.py (or wherever your main app's URLs are defined)

from django.urls import path, include
from .views import register_view, login_view

urlpatterns = [
    path("register/", register_view, name="register"),
    path("", login_view, name="login"),
    path("dashboard/", include("DASHBOARD.urls")),  # Include the dashboard app URLs
]
