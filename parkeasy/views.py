from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponse
from parkeasy.serializers import RegisterSerializer, LoginSerializer, VehicleSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.generics import ListAPIView
from .models import *
from rest_framework.permissions import AllowAny
from .permissions import IsAdmin
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken
from datetime import timedelta
from django.contrib.auth import get_user_model

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

# class CustomTokenRefreshView(TokenRefreshView):
#     def post(self, request, *args, **kwargs):
#         try:
#             data = super().post(request, *args, **kwargs).data
#             user = self.get_user_from_token(data.get('access'))
#             last_active = datetime.now() - timedelta(minutes=1)
#             if user.last_login < user.last_active:
#                 return Response({"message" : "User not active for too long"}, status=status.HTTP_403_Forbidden)
#             return Response(data)
#         except InvalidToken as e:
#             return Response({"detail" : str(e)}, status=status.HTTP_400_BAD_REQUEST)

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
            print('user.last_Active' ,user.last_active)
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
                user.last_active = now()
                user.save()
                refresh = RefreshToken.for_user(user)
                return Response({
                        'access' : str(refresh.access_token),
                        'refresh' : str(refresh)
                    })
            return Response({"error" : "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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


class ProtectedView(APIView):
    permission_classes = [IsAdmin]
    def get(self, request):
        return Response({"message" : "Welcome to the protected view"})



