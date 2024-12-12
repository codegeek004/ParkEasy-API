from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from parkeasy.models import *


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'email']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        role = validated_data.get('role', 'user')  # Default role is 'user'
        print('role', role)
        if role not in ['admin', 'user']:
            raise serializers.ValidationError({"role": "Invalid role. Choose either 'admin' or 'user'."})


        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data['email'],
            role=role
        )
        return user

class LoginSerializer(serializers.Serializer):
	username = serializers.CharField()
	password = serializers.CharField()


class VehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle
        fields = "__all__"
