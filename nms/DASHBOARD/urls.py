# dashboard/urls.py

from django.urls import path
from .views import logout_view, ping_operation

urlpatterns = [
    path("logout/", logout_view, name="logout"),
    path("", ping_operation, name="ping_operation"),
]
