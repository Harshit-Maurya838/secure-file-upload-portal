import os
import uuid
from django.db import models
from django_cryptography.fields import encrypt


import hashlib

def get_file_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    # Default to quarantine for new uploads
    return os.path.join('quarantine/', filename)

class UploadedFile(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending Scan'),
        ('CLEAN', 'Clean'),
        ('REJECTED', 'Rejected'),
    ]
    file = models.FileField(upload_to=get_file_path)
    description = encrypt(models.CharField(max_length=255, blank=True))
    hash = models.CharField(max_length=64, blank=True, editable=False)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.hash:
            sha256 = hashlib.sha256()
            for chunk in self.file.chunks():
                sha256.update(chunk)
            self.hash = sha256.hexdigest()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.file.name} - {self.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')}"
