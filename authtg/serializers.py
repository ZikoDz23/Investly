from rest_framework import serializers
from .models import UserProfile

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['user', 'wallet_address', 'private_key_encrypted', 'eth_address', 'tron_address']
        read_only_fields = ['user']  # Keep 'user' read-only, as it's set automatically
