# models.py
from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    wallet_address = models.CharField(max_length=255, blank=True, null=True)  # Store wallet address
    private_key_encrypted = models.TextField(blank=True, null=True)  # Store encrypted private key
    eth_address = models.CharField(max_length=255, blank=True, null=True)  # Ethereum address
    tron_address = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.user.username

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.userprofile.save()
