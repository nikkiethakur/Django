from rest_framework import serializers
# from django.contrib.auth.models import User
from .models import User, Employee

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'mobile']

class DesignationSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.full_name', read_only=True)
    designation = serializers.CharField()
    class Meta:
        model = Employee
        fields = ['id','full_name','designation', 'department']

class DepartmentSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.full_name', read_only=True)
    department = serializers.CharField()
    class Meta:
        model = Employee
        fields = ['id','full_name','department', 'designation']

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','full_name','email', 'password', 'mobile']

    def create(self, validated_data):
        user = User.objects.create_user(
        full_name = validated_data['full_name'],
        email = validated_data['email'],
        password = validated_data['password'],
        )
        return user

class LoginSerializer(serializers.Serializer):
        email = serializers.CharField(required=True)
        password = serializers.CharField(required=True, write_only = True)