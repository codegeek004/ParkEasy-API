from django.urls import path, re_path, include
from parkeasy.views import *
from allauth.socialaccount.urls import urlpatterns as social_urls


urlpatterns = [

    path('api/register/', RegisterView.as_view(), name="register"),
    path('api/login/', LoginView.as_view(), name="login"),
    path('', HomeView.as_view(), name="home"),
    path('vehicles/', VehicleView.as_view(), name='vehicles'),
    path('protected', ProtectedView.as_view(), name="home"), # error with permissions
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('slots/', SlotView.as_view(), name="slots-list-create"),
    path('slots/<int:pk>/', SlotView.as_view(), name="slots-operation-id"),
    #Multi-Factor authentication
    path('api/mfa/create/', TOTPCreateView.as_view(), name='mfa-create'),
    path('api/mfa/verify/', TOTPVerifyView.as_view(), name='mfa-verify'),
    # path('api/login/', LoginWith2FAView.as_view(), name='login-with-2fa')
    path('password/forgot/', ForgotPassword.as_view(), name='forgot-password'), # smtp error
    path('password/reset/<uidb64>/<token>/', ResetPassword.as_view(), name='reset-password'), # smtp error
    path('iplogin/', LoginAPIView.as_view(), name='iplogin'),


]
