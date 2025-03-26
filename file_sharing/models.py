# models.py
from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    kyber_public_key = models.BinaryField()  # Store as binary or base64-encoded string
    kyber_private_key = models.BinaryField()
    ecdsa_private_key = models.BinaryField(null=True, blank=True)
    ecdsa_public_key = models.BinaryField(null=True, blank=True)


class SharedFile(models.Model):
    sender = models.ForeignKey(User, related_name='sent_files', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_files', on_delete=models.CASCADE)
    file = models.FileField(upload_to='encrypted_files/')
    original_filename = models.CharField(max_length=255)
    nonce = models.BinaryField()  # Store nonce for AES-GCM
    tag = models.BinaryField()    # Authentication tag for AES-GCM
    encapsulated_key = models.BinaryField()
    signature = models.BinaryField()   # The Kyber encapsulated AES key
    created_at = models.DateTimeField(auto_now_add=True)    

from django.db import models
from django.contrib.auth.models import User

class Message(models.Model):
    sender = models.ForeignKey(User, related_name="sent_messages", on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name="received_messages", on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender} -> {self.receiver}: {self.content[:20]}"












