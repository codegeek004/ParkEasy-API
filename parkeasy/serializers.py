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
        #validated_data is the data we insert from the post method
        #checks the role in the validated_data dictionary of the serializer. 
        #If the role does not exist it will be user by default
        print('validated_Data: ', validated_data)
        role = validated_data.get('role', 'user')
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
