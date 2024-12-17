from django.urls import path, re_path
from parkeasy.views import *

urlpatterns = [

    path('accounts/register/', RegisterView.as_view(), name="register"),
    path('accounts/login/', LoginView.as_view(), name="login"),
    path('', HomeView.as_view(), name="home"),
    path('vehicles/', VehicleView.as_view(), name='vehicles'),
    path('protected', ProtectedView.as_view(), name="home"),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('slots/', SlotView.as_view(), name="slots-list-create"),
    path('slots/<int:pk>/', SlotView.as_view(), name="slots-operation-id"),
    #Multi-Factor authentication
    path('api/totp/create/', TOTPCreateView.as_view(), name='totp-create'),
    path('api/totp/verify/', TOTPVerifyView.as_view(), name='totp-verify'),
    path('api/login/', LoginWith2FAView.as_view(), name='login-with-2fa'),
    # path('api/sensitive/', SensitiveView.as_view(), name='sensitive-api'),
    ]