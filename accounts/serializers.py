from rest_framework import serializers
from .models import UserProfile

class SignupSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = UserProfile
        fields = ('username', 'email', 'password', 'confirm_password')
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Password and confirm password do not match")
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = UserProfile.objects.create_user(**validated_data)
        return user