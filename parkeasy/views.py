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





class SlotView(ListModelMixin, RetrieveModelMixin, CreateModelMixin, UpdateModelMixin, DestroyModelMixin, GenericAPIView):
    permission_classes = [AllowAny]
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

class slot_api:
    slot_endpoint = 'http://127.0.0.1:8000/slots/'
    def get_data(request):
        try:
            response = requests.get(slot_endpoint)
            data = response.json()
        except Exception as e:
            pass
        return render(request, 'slots.html', {'api_data' : data})






