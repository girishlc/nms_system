from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser  # Use this if you created a custom user model


class RegisterForm(UserCreationForm):
    class Meta:
        model = CustomUser  # Use this if you created a custom user model
        fields = ["username", "password1", "password2"]


class LoginForm(AuthenticationForm):
    username = forms.CharField(label="Username", max_length=150)
    password = forms.CharField(label="Password", widget=forms.PasswordInput)
