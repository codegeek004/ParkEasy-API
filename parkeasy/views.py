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
    def post(self, request, *args, **kwargs):
        try: 
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"message": "Refresh Token is required."}, status=status.HTTP_400_BAD_REQUEST)
            
            token = RefreshToken(refresh_token)
            user_id = token["user_id"]

            user = User.objects.get(id=user_id)

            # Check for inactivity (more than 5 minutes)
            if user.last_active and now() - user.last_active > timedelta(minutes=5):
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
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(username=serializer.validated_data['username'],
                                password=serializer.validated_data['password'])
            if user is not None:
                refresh = RefreshToken.for_user(user)
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
    def get(self, request):
        return Response({"message" : "Welcome to the protected view"})

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

class SlotView(ListModelMixin, RetrieveModelMixin, CreateModelMixin, UpdateModelMixin, DestroyModelMixin, GenericAPIView):
    permission_classes = [AllowAny]
    queryset = Slots.objects.all()
    serializer_class = SlotSerializer
    
    #Helper function to retrieve an object by id or return 404 code.
    def get_object_or_404(self, SlotID):
        try:
            return Slots.objects.get(id=SlotID)
        except Slots.DoesNotExist:
            raise Response({"message" : f"slot {SlotID} not found"}, status=status.HTTP_404_NOT_FOUND)

    def list(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        SlotID = kwargs.get('pk')
        slot = self.get_object_or_404(SlotID)
        serializer = self.get_serializer(slot)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

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
        SlotID = kwargs.get('pk')
        if SlotID:
            slot = self.get_object_or_404(SlotID)
            serializer = self.get_object_or_404(slot, data=request.data, parital=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.save)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message" : "SlotID is required"}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        SlotID = kwargs.get('pk')
        if SlotID:
            slot = self.get_object_or_404(SlotID)
            slot.delete()
            return Response({"message" : "Slot {SlotID} deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        return Response({"message" : "SlotID is required for deleting."}, status=status.HTTP_400_BAD_REQUEST)









