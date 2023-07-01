from datetime import timedelta
from typing import Optional

from django.conf import settings
from django.db import models
from django.utils import timezone


class Configuration(models.Model):
    name = models.CharField(max_length=256, unique=True)
    value = models.BinaryField()

    @classmethod
    def get(cls, name: str, default=None) -> Optional[bytes]:
        try:
            return cls.objects.get(name=name).value
        except cls.DoesNotExist:
            return default

    @classmethod
    def set(cls, name: str, value: bytes):
        obj, _ = cls.objects.get_or_create(name=name)
        obj.value = value
        obj.save()

class Session(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)
    key_id = models.BinaryField(unique=True, db_index=True)
    key = models.BinaryField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class User(models.Model):
    username = models.CharField(max_length=128, unique=True, db_index=True)
    password_salt = models.BinaryField()
    password_hash = models.BinaryField()
    last_pull = models.DateTimeField(auto_now=True)

    @property
    def online(self):
        return self.last_pull > timezone.now() - timedelta(seconds=settings.ONLINE_TIMEOUT)


class Key(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='keys')
    key_id = models.BinaryField(unique=True, db_index=True)
    public_key = models.BinaryField(unique=True)
    encrypted_private_key = models.BinaryField(unique=True)
    is_active = models.BooleanField(default=False)
    is_used = models.BooleanField(default=False)
    is_rsa = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class ChatMessage(models.Model):
    sender = models.ForeignKey('User', on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey('User', on_delete=models.CASCADE, related_name='received_messages')
    group = models.ForeignKey('Group', on_delete=models.CASCADE, null=True, blank=True)
    message = models.BinaryField()
    recipient_key_id = models.BinaryField(null=True, blank=True)
    sender_dh_public_key = models.BinaryField()
    sender_rsa_public_key = models.BinaryField()
    key_id = models.BinaryField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Group(models.Model):
    name = models.CharField(max_length=256, unique=True)
    admin = models.ForeignKey('User', on_delete=models.CASCADE)
    members = models.TextField()
