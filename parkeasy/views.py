from django.views import View
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponse
from parkeasy.serializers import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.generics import ListAPIView
from .models import *
from rest_framework.permissions import AllowAny
from .permissions import IsAdmin
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken
from datetime import timedelta
from django.contrib.auth import get_user_model

#mixins
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin, CreateModelMixin, UpdateModelMixin, DestroyModelMixin
from rest_framework.generics import GenericAPIView
from django.shortcuts import get_object_or_404

#multi-factor authentication
from rest_framework import views, permissions
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice

#allauth
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter

#forgot password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .models import PasswordReset
import os
from rest_framework import generics
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode
from decouple import config

#for ip address tracing and blocking the attacker
from django.core.cache import cache
from django.utils.timezone import now


User = get_user_model()

class HomeView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        return Response({"message" : "Welcome to the JWT API"})

class RegisterView(APIView):
    print('register view class mai gaya')
    permission_classes = [AllowAny]
    def post(self, request):
        print('post method mai gaya')
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            print('serializer is valid mai gaya')
            user = serializer.save()
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        print('print serializer is valid wale if ke bahar')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomTokenRefreshView(TokenRefreshView):
    print('custome refresh view mai gaya')
    def post(self, request, *args, **kwargs):
        try: 
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"message": "Refresh Token is required."}, status=status.HTTP_400_BAD_REQUEST)
            
            token = RefreshToken(refresh_token)
            user_id = token["user_id"]

            user = User.objects.get(id=user_id)

            # Check for inactivity (more than 5 minutes)
            if user.last_active and now() - user.last_active > timedelta(minutes=10):
                return Response({"message": "User was inactive for more than 5 minutes"}, status=status.HTTP_401_UNAUTHORIZED)

            # Update user's last active time
            user.last_active = now()
            print('user.last_Active', user.last_active)
            user.save()

            # Generate new access token
            access_token = str(token.access_token)
            return Response({"new access token": access_token})
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    print('login view mai gaya')
    # 
    permission_classes = [AllowAny]
    def post(self, request):
        remember_me = request.data.get('remember_me', False)
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(username=serializer.validated_data['username'],
                                password=serializer.validated_data['password'])
            if user is not None:
                
                refresh = RefreshToken.for_user(user)
                if remember_me:
                    refresh.set_exp(lifetime=timedelta(days=7))
                user.last_active = now()
                user.latest_token = refresh.access_token['jti']
                user.save()

                return Response({
                        'access' : str(refresh.access_token),
                        'refresh' : str(refresh)
                    })
            return Response({"error" : "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            user = request.user

            # Invalidate the active token
            active_token = ActiveToken.objects.get(user=user)
            token = RefreshToken(active_token.refresh_token)
            token.blacklist()  # Blacklist the token
            active_token.delete()  # Remove from the database

            return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)

        except ActiveToken.DoesNotExist:
            return Response({"error": "No active session found."}, status=status.HTTP_400_BAD_REQUEST)

class ForgotPassword(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = request.data['email']
        user = CustomUser.objects.filter(email__iexact=email).first()

        if user:
            token = token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            # reset = PasswordReset(email=email, token=token)
            # reset.save()
            try:
                print('try mai gay')
                print(config("PASSWORD_RESET_BASE_URL"))
                print("User PK:", user.pk)
                print("Token:", token)
                print("Encoded PK:", urlsafe_base64_encode(force_bytes(user.pk)))
                reset_url = f"{config('PASSWORD_RESET_BASE_URL')}/{urlsafe_base64_encode(force_bytes(user.pk))}/{token}"
                print('reset_url',reset_url)
                send_mail(
                        subject = "Reset Your Password",
                        message = f"Click the link below to reset your password:\n\n{reset_url}",
                        from_email = "yashvaishnav1411@gmail.com",
                        recipient_list = [email],
                        fail_silently = False,
                    )
                return Response({"success" : "We have sent you an email"}, status=status.HTTP_200_OK)
            except Exception as e:
                print('except mai gaya')
                print('The error is', e)

            
        return Response({"message" : "credentials not found"}, status=status.HTTP_400_BAD_REQUEST)

class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = []

    def post(self, request, uidb64, token):
        try:
            user_id = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=user_id)

            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                return Response({"error" : "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)

            new_password = serializer.validated_data['new_password']
            user.set_password(new_password)
            user.save()



            return Response({"success" : "Password reset successful"}, status=status.HTTP_201_CREATED)

        except(TypeError, ValueError, CustomUser.DoesNotExist):
            return Response({"error" : "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)



class ProtectedView(APIView):
    permission_classes = [IsAdmin]
    def post(self, request):
        token = request.data.get('token')
        user = request.user   
        devices = list(devices_for_user(user))
        device = devices[0] if devices else None
        if device and device.verify_token(token):
            return Response({"detail" : "access granted"}, status=status.HTTP_200_OK)
        return Response({"message" : "TOTP is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

class VehicleView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        vehicles = Vehicle.objects.all()
        print(vehicles)
        serializer = VehicleSerializer(vehicles, many=True)
        print(serializer.data)
        return Response(serializer.data)
    def post(self, request, format=None):
        serializer = VehicleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

############################ Multi-Factor Authentication ##########################
def get_user_totp_device(user, confirmed=None):
    print('get totp device mai gaya')
    devices = devices_for_user(user, confirmed=confirmed)  # devices is a generator
    for device in devices:  # Iterate through the generator
        print('for device mai gaya')
        if isinstance(device, TOTPDevice):
            print('device:', device)
            return device
    return None  # Return None if no TOTPDevice exists


class TOTPCreateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
        print('Existing device:', device)

        # If no device exists, create a new one
        if not device:
            device = user.totpdevice_set.create(confirmed=False)

        # Retrieve the configuration URL
        url = device.config_url
        print('Device Config URL:', url)
        return Response({"qr_url" : url}, status=status.HTTP_201_CREATED)


class TOTPVerifyView(views.APIView):
    #endpoint to verify or enable a TOTP device
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        token = request.data.get('token')
        user = request.user
        device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
        if not device:
            return Response({"message" : "No TOTP device found"}, status=status.HTTP_400_BAD_REQUEST)

        if device.verify_token(token):
            device.confirmed = True
            device.save()
            return Response({"message" : "TOTP verifid"}, status=status.HTTP_200_OK)
        return Response({"message" :"Invalid or expired oken"}, status=status.HTTP_400_BAD_REQUEST)



####################DFA end########################


########################Blocking Attacker's IP Address#############################

MAX_ATTEMPTS = 2
BLOCK_DURATION = 60*15 #in minutes

def get_client_id(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
        print('ip', ip)
    return ip 

class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        user = request.user
        username = request.data.get('username')
        password = request.data.get('password')
        ip_address = get_client_id(request)
        print(ip_address)


        failed_attempts = cache.get(f"failed_attempts_{ip_address}", 0)

        if failed_attempts >=MAX_ATTEMPTS:
            return Response({"error" : "IP address blocked"}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=username, password=password)
        print(failed_attempts, 'fail')
        if user is None:
            cache.set(f"failed_attempts_{ip_address}", failed_attempts+1, timeout=BLOCK_DURATION)
            return Response({"message" : "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        refresh = RefreshToken.for_user(user)

                
        cache.delete(f"failed_attempts_{ip_address}")
        return Response({
                        'access' : str(refresh.access_token),
                        'refresh' : str(refresh)
                    })



class SlotView(ListModelMixin, RetrieveModelMixin, CreateModelMixin, UpdateModelMixin, DestroyModelMixin, GenericAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Slots.objects.all()
    serializer_class = SlotSerializer
    
    def get_object_or_404(self, pk):
        try:
            return Slots.objects.get(SlotID=pk)
        except Slots.DoesNotExist:
            raise Response({"message": f"Slot {pk} not found"}, status=status.HTTP_404_NOT_FOUND)

    def get(self, request, *args, **kwargs):
        pk = kwargs.get('pk')
        if pk:
            slot = self.get_object_or_404(pk)
            serializer = self.get_serializer(slot)
            return Response(serializer.data)
        else:
            return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        SlotID = kwargs.get('pk')
        if SlotID:
            slot = self.get_object_or_404(SlotID)
            serializer = self.get_serializer(slot, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message" : "SlotID is required"}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):
        print('patch mai gaya')
        SlotID = kwargs.get('pk')
        if SlotID:
            slot = self.get_object_or_404(SlotID)
            serializer = self.get_serializer(slot, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message" : "SlotID is required"}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        SlotID = kwargs.get('pk')
        print('SlotID', SlotID)
        if SlotID:
            slot = self.get_object_or_404(SlotID)
            print('slot', slot)
            slot.delete()
            return Response({"message" : "Slot {SlotID} deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        return Response({"message" : "SlotID is required for deleting."}, status=status.HTTP_400_BAD_REQUEST)


###frontend view######
from django.shortcuts import render
import requests

class slot_api(View):
    permission_classes = [IsAuthenticated]
    slot_endpoint = 'http://127.0.0.1:8000/slots/'
    def get(self, request):
        user = request.user
        print('user', user)
        try:
            headers = {
                "Authorization" : f"Bearer {request.user.auth_token}"
            }
            print('try mai gaya')
            response = requests.get(self.slot_endpoint, headers=headers)
            print(response, 'response')
            response.raise_for_status()
            #parsing the json payload
            data = response.json()
            print(data)

        except Exception as e:
            print('exception hai', e)
        return render(request, 'slots.html', {'api_data' : data})

    # def post_data(r)



###########################Oauth###############################

from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from parking import settings

class GoogleLogin(SocialLoginView):
    # class GoogleAdapter(GoogleOAuth2Adapter):
    #     access_token_url = "https://oauth2.googleapis.com/token"
    #     authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
    #     profile_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    #     adapter_class = GoogleOAuth2Adapter 
    #     callback_url = "http://127.0.0.1:8000/oauth/"
    #     client_class = OAuth2Client
    adapter_class = GoogleOAuth2Adapter
    callback_url = settings.GOOGLE_OAUTH_CALLBACK_URL
    client_class = OAuth2Client

from urllib.parse import urljoin

import requests
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

# class GoogleLoginCallback(APIView):

#     permission_classes = [IsAuthenticated]
#     def get(self, request, *args, **kwargs):
#         """
#         Handles the Google OAuth callback and exchanges the authorization code for tokens.
#         """

#         code = request.GET.get("code")
#         print('code', code)

#         if not code:
#             return Response({"detail": "Authorization code not provided."}, status=status.HTTP_400_BAD_REQUEST)
        
#         # Google token exchange URL
#         token_endpoint_url = "https://oauth2.googleapis.com/token"
#         print('token_endpoint_url', token_endpoint_url)
        
#         # Prepare data for the POST request to Google
#         response = requests.post(
#             url=token_endpoint_url,
#             data={
#                 "code": code,
#                 "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
#                 "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
#                 "redirect_uri": settings.GOOGLE_OAUTH_CALLBACK_URL,
#                 "grant_type": "authorization_code",  # Standard OAuth2 authorization code grant type
#             },
#         )

#         # If the response from Google is successful
#         if response.status_code == 200:
#             tokens = response.json()  # Contains access_token and refresh_token
#             return Response(tokens, status=status.HTTP_200_OK)
#         else:
#             print("Error response from Google:", response.json())
#             return Response({"detail": "Error fetching tokens from Google."}, status=status.HTTP_400_BAD_REQUEST)
import requests
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from django.urls import reverse
from urllib.parse import urljoin

import requests
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
import requests
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.conf import settings
class GoogleLoginCallback(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request, *args, **kwargs):
        """
        This is the callback URL where Google redirects after successful authentication.
        After the code is exchanged for a token, the user will be logged in and JWT tokens will be generated.
        """
        code = request.GET.get("code")
        
        if not code:
            return Response({"error": "Code not provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Exchange the authorization code for an access token
        token_endpoint_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_OAUTH_CALLBACK_URL,
            "grant_type": "authorization_code",
        }
        
        response = requests.post(token_endpoint_url, data=data)
        response_data = response.json()
        
        # Check if the response contains an access token
        if "access_token" not in response_data:
            return Response({"error": "Unable to fetch access token from Google"}, status=status.HTTP_400_BAD_REQUEST)

        access_token = response_data["access_token"]

        # Fetch user information using the access token
        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(user_info_url, headers=headers)
        
        if user_info_response.status_code != 200:
            return Response({"error": "Unable to fetch user info from Google"}, status=status.HTTP_400_BAD_REQUEST)
        
        user_data = user_info_response.json()
        email = user_data.get("email")
        username = user_data.get("name")  # You can use `name` or another field as username

        if not email:
            return Response({"error": "Email not found in Google user info"}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate or create a new user based on the email
        user = get_user_model().objects.filter(email=email).first()

        if not user:
            # User does not exist, create a new one
            user = get_user_model().objects.create_user(
                username=username, email=email
            )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        # Optional: set an expiration date for the refresh token
        if 'remember_me' in request.GET:
            refresh.set_exp(lifetime=timedelta(days=7))
        
        user.last_active = now()
        user.latest_token = access_token
        user.save()

        return Response({
            'access': access_token,
            'refresh': refresh_token
        })
class LoginGooglePage(View):
    def get(self, request, *args, **kwargs):
        return render(
            request,
            "login.html",
            {
                "google_callback_uri": settings.GOOGLE_OAUTH_CALLBACK_URL,
                "google_client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            },
        )


#########################Oauth end#############################





