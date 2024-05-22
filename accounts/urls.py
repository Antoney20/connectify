from django.urls import path
from .views import UserSignUp

urlpatterns = [
    path('register/', UserSignUp.as_view(), name='user-registration'),
]