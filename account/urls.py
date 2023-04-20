from django.contrib import admin
from django.urls import path
from account.views import (UserRegistrationView, UserLoginView, UserProfileView, UserChangePasswordView,
                           SendPasswordResetEmailView, UserPasswordResetView)

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='change-password'),
    path('resetpasswordemail/', SendPasswordResetEmailView.as_view(), name='send-password-email-reset'),
    path('resetpassword/<uid>/<token>', UserPasswordResetView.as_view(), name='password-reset')
]