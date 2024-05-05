from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.admin.models import LogEntry  # Import the LogEntry model
from .models import *

# Unregister the LogEntry model from the admin site
# admin.site.unregister(LogEntry)



class OtpTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "otp_code")

admin.site.register(OtpToken, OtpTokenAdmin)
admin.site.register(URL)
admin.site.register(OnionURL)
admin.site.register(PhishingURLClassification)
admin.site.register(UserLog)
