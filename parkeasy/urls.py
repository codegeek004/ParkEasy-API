from django.urls import path, re_path, include
from parkeasy.views import *
from allauth.socialaccount.urls import urlpatterns as social_urls

#oauth


from .views import GoogleLogin, GoogleLoginCallback, LoginGooglePage

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
    path('api/mfa/create/', TOTPCreateView.as_view(), name='mfa-create'),
    path('api/mfa/verify/', TOTPVerifyView.as_view(), name='mfa-verify'),
    # path('api/login/', LoginWith2FAView.as_view(), name='login-with-2fa')
    path('password/forgot/', ForgotPassword.as_view(), name='forgot-password'),
    path('password/reset/<uidb64>/<token>/', ResetPassword.as_view(), name='reset-password'),
    path('myslots/', slot_api.as_view(), name='slot-view'),
    path('iplogin/', LoginAPIView.as_view(), name='iplogin'),
    path("login/", LoginGooglePage.as_view(), name="login"),
    path("api/v1/auth/", include("dj_rest_auth.urls")),  # for dj_rest_auth
    re_path(r"^api/v1/auth/accounts/", include("allauth.urls")),  # for allauth
    path("api/v1/auth/registration/", include("dj_rest_auth.registration.urls")),
    path("api/v1/auth/google/", GoogleLogin.as_view(), name="google_login"),
    # path("api/v1/auth/google/callback/", GoogleLoginCallback.as_view(), name="google_login_callback"),
    path('rest-auth/google/', GoogleLogin.as_view(), name='rest_auth_google_login'),  # add this line
    path('api/v1/auth/google/callback/', GoogleLoginCallback.as_view(), name='google_login_callback'),

]
