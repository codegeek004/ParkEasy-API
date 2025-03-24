from django.views import View
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import *
from parkeasy.serializers import *
from rest_framework.generics import ListAPIView
from .models import *
from .permissions import IsAdmin
from datetime import timedelta
from django.contrib.auth import get_user_model

#jwt
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken

#mixins
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin, CreateModelMixin, UpdateModelMixin, DestroyModelMixin
from rest_framework.generics import GenericAPIView
from django.shortcuts import get_object_or_404

#multi-factor authentication
from rest_framework import views, permissions
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice

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
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomTokenRefreshView(TokenRefreshView):

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
    def get(self, request):
        return Response({"success" : "You are in Protected View"}, status=status.HTTP_200_OK)


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



####################MFA end########################


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


###################### application endpoints ################################
class SlotView(ListModelMixin, RetrieveModelMixin, CreateModelMixin, UpdateModelMixin, DestroyModelMixin, GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SlotSerializer
    queryset = Slots.objects.all()
    
    # if you want to retrieve rows based on pk like 'http://127.0.0.1:8000/slots/1/'
    def get_object_or_404(self, pk):
        print('inside get objects or 404')
        try:
            return Slots.objects.get(SlotID=pk)
        except Slots.DoesNotExist:
            return Response({"message": f"Slot {pk} not found"}, status=status.HTTP_404_NOT_FOUND)

    # if you want to fetch all the rows
    def get(self, request, *args, **kwargs):
        print('inside get self, request')
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
        print('SlotID', SlotID)
        if SlotID:
            slot = self.get_object_or_404(SlotID)
            serializer = self.get_serializer(slot, data=request.data)
            if serializer.is_valid():
                print('serializer is valid')
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message" : "SlotID is required"}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):
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
            return Response({"message" : f"Slot {SlotID} deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        return Response({"message" : "SlotID is required for deleting."}, status=status.HTTP_400_BAD_REQUEST)


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






