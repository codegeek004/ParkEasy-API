from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from parkeasy.models import *
from dj_rest_auth.registration.serializers import RegisterSerializer

User = get_user_model()

def CustomRegisterSerializer(RegisterSerializer):
    def save(self, request):
        return super().save(request)

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'email', 'role']
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

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.RegexField(
            regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
            write_only = True,
            error_messages = {"invalid" : ("Password must be 8 digits long with at least one capital and one special charactor")}
        )
    confirm_password = serializers.CharField(write_only=True, required=True)

class LoginSerializer(serializers.Serializer):
	username = serializers.CharField()
	password = serializers.CharField()


class VehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle
        fields = "__all__"

class SlotSerializer(serializers.ModelSerializer):
    class Meta:
        model = Slots 
        # fields = ['space', 'price', 'total_slots']
        fields = "__all__"
    def create(self, validated_data):
        space = validated_data.get('space')
        if space not in ['car/jeep', '2-wheeler', 'heavy-vehicle']:
            raise serializers.ValidationError({"space": "Invalid space selected"})
        slot = Slots.objects.create(
                space = space,
                price = validated_data['price'],
            )
        return slot


