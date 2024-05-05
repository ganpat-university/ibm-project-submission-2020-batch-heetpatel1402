# verify_otp.py

from django.shortcuts import render
from django.core.cache import cache

def verify_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp = request.POST.get('otp_code')
        cached_otp = cache.get(email)
        if cached_otp == otp:
            # OTP is correct, handle verification success
            return render(request, 'verification_success.html')
        else:
            # OTP is incorrect, handle verification failure
            return render(request, 'verification_failure.html')
    return render(request, 'verify_otp.html')
