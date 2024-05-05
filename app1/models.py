from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.translation import gettext_lazy as _
from django.conf import settings
import secrets



from django.db import models
from django.contrib.auth.models import AbstractUser, User
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.utils import timezone
import secrets
import datetime


class OtpToken(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otp_token")
    otp_code = models.CharField(max_length=6)
    otp_created_at = models.DateTimeField(auto_now_add=True)
    otp_expires_at = models.DateTimeField()

    def __str__(self):
        return self.user.username
    

class URL(models.Model):
    url = models.URLField(max_length=200)
    result = models.CharField(max_length=10, choices=[('Safe', 'Safe'), ('Phishing', 'Phishing')], blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, default=None)
    # generated_by_input_url = models.BooleanField(default=False)  # New field
    def _str_(self):
        return f"{self.url} - {self.result}"

from django.db import models

class OnionURL(models.Model):
    url = models.URLField()
    result = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
    


class PhishingURLClassification(models.Model):
    url = models.URLField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    result = models.CharField(max_length=10)  # Safe or Phished
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url

class UserLog(models.Model):
    user = models.CharField(max_length = 200)
    action = models.CharField(max_length = 200, blank=True, null=True)
    phish_url = models.URLField(blank=True, null=True)
    phish_result = models.CharField(max_length=10,  blank=True, null=True)
    onion_url = models.URLField(blank=True, null=True)
    onion_result = models.TextField(blank=True, null=True)
    url = models.URLField(max_length=200, blank=True, null=True)
    result = models.CharField(max_length=10, choices=[('Safe', 'Safe'), ('Phishing', 'Phishing')], blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    
    def __str__(self):
        return f"{self.user} - {self.action}"
    
    
# Integrated Testing
# Link enumeration
#Phishing Detection
#Login
#Registration