from sqlite3 import IntegrityError
import time
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.core.cache import cache

from app1.models import *
from .forms import SignUpForm
# from .models import CustomUser
import random
from django.utils import timezone
# Create your views here.

# @login_required(login_url='login')
def home(request):
    return render(request, "index.html")

def loginpage(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            UserLog.objects.create(user = request.user, action = "Login")
            return redirect("user")
        else:
            return render(request, 'login.html', {'error_message': 'Invalid username or password'})
    else:
        return render(request, 'login.html')
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from django.utils import timezone
def sign_up(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user=form.save()
            # Generate OTP code
            otp_code = get_random_string(length=6, allowed_chars='0123456789')
            # Set OTP expiration time (e.g., 5 minutes from now)
            otp_expires_at = timezone.now() + timezone.timedelta(minutes=5)
            # Save OTP token in the database
            OtpToken.objects.create(user=user, otp_code=otp_code, otp_expires_at=otp_expires_at)
            # Send OTP email
            subject = "Email Verification"
            message = render_to_string('otp_email.html', {'otp_code': otp_code})
            sender = "your_email@example.com"  # Update with your sender email address
            receiver = [user.email]
            send_mail(subject, message, sender, receiver)
            # Redirect to the verify-email page
            UserLog.objects.create(user = request.user, action = "Registeration Successful", created_at=timezone.now())
            return redirect('verify_email', username=user.username)
        else:
            messages.warning(request, 'username or email are already taken')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form ,'error_message': 'Invalid username or password'})
         
    # email = request.POST.get('email')
    #         if email:
    #             otp = ''.join(random.choices('0123456789', k=6))
    #             cache.set(email, otp, timeout=300)
    #             send_mail(
    #                 'OTP Verification',
    #                 f'Your OTP is: {otp}',
    #                 settings.EMAIL_HOST_USER,
    #                 [email],
    #                 fail_silently=False,
    #             )
    #             return redirect('verify_email',)
    # else:

# def verify_otp(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         entered_otp = request.POST.get('otp_code')
#         stored_otp = cache.get(email)
#         if stored_otp == entered_otp:
#             cache.delete(email)
#             return redirect('login')
#         else:
#             error_message = 'Invalid OTP. Please try again.'
#             return render(request, 'verify_otp.html', {'email': email, 'error_message': error_message})
#     else:
#         email = request.GET.get('email')
#         return render(request, 'verify_otp.html', {'email': email})

def success(request):
    return render(request, 'success.html')

def logoutuser(request):
    if request.user.is_authenticated:
        UserLog.objects.create(user=request.user, action="Logout", created_at=timezone.now())
        logout(request)
    return redirect('home')

from django.utils.crypto import get_random_string
from django.utils import timezone
from .models import OtpToken

def verify_email(request, username):
    user = User.objects.get(username=username)
    user_otp = OtpToken.objects.filter(user=user).last()
    
    if request.method == 'POST':
        entered_otp = request.POST.get('otp_code', '')  # Get entered OTP from the form
        stored_otp = user_otp.otp_code  # Get stored OTP from the database
        
        if entered_otp == stored_otp:  # Compare entered and stored OTPs
            if user_otp.otp_expires_at > timezone.now():
                user.is_active = True
                user.save()
                messages.success(request, "Account activated successfully!! You can Login.")
                UserLog.objects.create(user = request.user, action = "Account Activated", created_at=timezone.now())
                return redirect('login')
            else:
                messages.warning(request, "The OTP has expired, get a new OTP!")
                return redirect("verify_email", username=user.username)
        else:
            print("User OTP:", user_otp)
            print("Stored OTP:", user_otp.otp_code)
            print("OTP Expiry:", user_otp.otp_expires_at)
            print("Current Time:", timezone.now())
            messages.warning(request, "Invalid OTP entered, enter a valid OTP!")
            return redirect("verify_email", username=user.username)
        
    context = {}
    return render(request, "verify_token.html", context)
 
# def verify_email(request, username):
#     user = User.objects.get(username=username)
#     user_otp = OtpToken.objects.filter(user=user).last()           
    
#     if request.method == 'POST':
#         if user_otp.otp_code == request.POST['otp_code']:
#             if user_otp.otp_expires_at > timezone.now():
#                 user.is_active = True
#                 user.save()
#                 messages.success(request, "Account activated successfully!! You can Login.")


#                 return redirect("signin")
#             else:
#                 messages.warning(request, "The OTP has expired, get a new OTP!")
#                 return redirect("verify_ email", username=user.username)
#         else:
#             print("User OTP:", user_otp)
#             print("Stored OTP:", user_otp.otp_code)
#             print("OTP Expiry:", user_otp.otp_expires_at)
#             print("Current Time:", timezone.now())
#             messages.warning(request, "Invalid OTP entered, enter a valid OTP!")
#             return redirect("verify_email", username=user.username)
         

  
#     context = {}
#     return render(request, "verify_token.html", context)
from django.contrib.auth import get_user_model
import random

def resend_otp(request):
    if request.method == 'POST':
        user_email = request.POST["otp_email"]
        try:
            user = get_user_model().objects.get(email=user_email)
        except get_user_model().DoesNotExist:
            messages.warning(request, "This email doesn't exist in the database")
            return redirect("resend-otp")

        # Check if an OTP token already exists for the user
        try:
            otp = OtpToken.objects.get(user=user)
            # Update the existing OTP token or delete it if necessary
            otp.otp_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])  # Generate a new OTP
            otp.otp_expires_at = timezone.now() + timezone.timedelta(minutes=5)
            otp.save()
        except OtpToken.DoesNotExist:
            # Create a new OTP token if it doesn't exist
            otp = OtpToken.objects.create(user=user, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5),
                                           otp_code=''.join([str(random.randint(0, 9)) for _ in range(6)]))
        except IntegrityError:
            # Handle the case where multiple OTP tokens exist for the same user
            messages.error(request, "Multiple OTP tokens found for this user. Please contact support.")
            return redirect("resend-otp")

        subject = "Email Verification"
        message = f"""
Hi {user.username}, here is your OTP {otp.otp_code} 
it expires in 5 minute, use the URL below to redirect back to the website
http://127.0.0.1:8000/verify-email/{user.username}
"""
        sender = "heetpatel20@gnu.ac.in"
        receiver = [user.email, ]

        send_mail(
            subject,
            message,
            sender,
            receiver,
            fail_silently=False,
        )
        messages.success(request, "A new OTP has been sent to your email address")
        return redirect("verify_email", username=user.username)

    context = {}
    return render(request, "resend_otp.html", context)


def user_home(request):
    return render(request, "index2.html", {'user': request.user})

import numpy as np
from .utils import clf
from django.shortcuts import render, redirect
from .models import URL
from .utils import check_onion_url, FeatureExtraction

# def input_url(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         urls_to_check = check_onion_url(url)
#         for link in urls_to_check:
#             feature_extractor = FeatureExtraction(link)
#             features = np.array([feature_extractor.features])
#             prediction = clf.predict(features)
#             if prediction == 1: 
#                 result = 'Safe'
#             else:
#                 result = 'Phishing'
#             URL.objects.create(url=link, result=result)
#         return redirect('results')
#     return render(request, 'url_checker.html')

# def results(request):
#     urls = URL.objects.all()
#     return render(request, 'results.html', {'urls': urls})
# from django.shortcuts import render, redirect
# from .models import URL
# from .utils import check_onion_url, FeatureExtraction

# def input_url(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         urls_to_check = check_onion_url(url)
#         for link in urls_to_check:
#             feature_extractor = FeatureExtraction(link)
#             features = np.array([feature_extractor.features])
#             prediction = clf.predict(features)
#             if prediction == 1:
#                 result = 'Safe'
#             else:
#                 result = 'Phishing'
#             URL.objects.create(url=link, result=result)
#         return redirect('results')
#     return render(request, 'url_checker.html')

# def results(request):
#     urls = URL.objects.all()
#     return render(request, 'results.html', {'urls': urls})
from django.shortcuts import render, redirect
from .models import URL
from .utils import check_onion_url, FeatureExtraction
import matplotlib.pyplot as plt
import os

def input_url(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        urls_to_check = check_onion_url(url)
        session_results = []
        for link in urls_to_check:
            feature_extractor = FeatureExtraction(link)
            features = np.array([feature_extractor.features])
            prediction = clf.predict(features)  # Assuming clf is your trained classifier
            if prediction == 1:
                result = 'Safe'
            else:
                result = 'Phishing'
            session_results.append({'url': link, 'result': result})
            URL.objects.create(url=link, result=result, user= request.user)
            UserLog.objects.create(user = request.user, action = "Integrated Checking", url= link, result= result, created_at=timezone.now())
        request.session['session_results'] = session_results
        return redirect('results')
    return render(request, 'url_checker.html')

# def results(request):
#     session_results = request.session.get('session_results', [])
    
#     # Calculate counts of safe and phishing links
#     safe_count = sum(1 for r in session_results if r['result'] == 'Safe')
#     phished_count = sum(1 for r in session_results if r['result'] == 'Phishing')
    
#     # Generate pie chart
#     labels = ['Safe', 'Phishing']
#     counts = [safe_count, phished_count]
#     plt.figure(figsize=(6, 6))
#     plt.pie(counts, labels=labels, autopct='%1.1f%%', startangle=140)
#     plt.title('Link Classification')
#     pie_chart_path = os.path.join('static', 'pie_chart.png')
#     plt.savefig(pie_chart_path)
#     plt.close()

#     # Pass the visual representation paths along with the session_results to the template
#     return render(request, 'results.html', {'urls': session_results, 'pie_chart_path': pie_chart_path})
# def results(request):
#     session_results = request.session.get('session_results', [])
    
#     safe_count = sum(1 for r in session_results if r['result'] == 'Safe')
#     phished_count = sum(1 for r in session_results if r['result'] == 'Phishing')
#     print(safe_count)
#     print(phished_count)
#     total = safe_count+phished_count
#     print(total)
    
#     labels = ['Safe', 'Phishing']
#     counts = [safe_count, phished_count]
# views.py

def results(request):
    session_results = request.session.get('session_results', [])
    
    safe_count = sum(1 for r in session_results if r['result'] == 'Safe')
    phished_count = sum(1 for r in session_results if r['result'] == 'Phishing')
    total = safe_count + phished_count
    
    labels = ['Safe', 'Phishing']
    counts = [safe_count, phished_count]
    
    return render(request, 'results.html', {'urls': session_results, 'counts': counts, 'labels': labels, 'total':total})

    # plt.figure(figsize=(6, 6))
    # plt.pie(counts, labels=labels, autopct='%1.1f%%', startangle=140)
    # plt.title('Link Classification')
    # # Save the pie chart image to the static directory
    # pie_chart_path = os.path.join(settings.STATIC_ROOT, 'pie_chart.png')
    # plt.savefig(pie_chart_path)
    # plt.close() 'pie_chart_path': '/static/pie_chart.png'

    return render(request, 'results.html', {'urls': session_results})

# def input_url(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         urls_to_check = check_onion_url(url)
#         session_results = []
#         for link in urls_to_check:
#             feature_extractor = FeatureExtraction(link)
#             features = np.array([feature_extractor.features])
#             prediction = clf.predict(features)
#             if prediction == 1:
#                 result = 'Safe'
#             else:
#                 result = 'Phishing'
#             # Store the result in session variable
#             session_results.append({'url': link, 'result': result})
#             URL.objects.create(url=link, result=result)
#         # Store session_results in session variable
#         request.session['session_results'] = session_results
#         return redirect('results')
#     return render(request, 'url_checker.html')

# def results(request):
#     # Retrieve session_results from session variable
#     session_results = request.session.get('session_results', [])
#     # Clear session_results from session variable
#     request.session['session_results'] = []
#     return render(request, 'results.html', {'urls': session_results})

from .models import OnionURL
from .domainutil import check_onion_url_domain
def subdomain_check(request):
    return render(request, 'domain_url_checker.html')

# def process_url(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         result = check_onion_url_domain(url)
#         return render(request, 'domain_result.html', {'result': result})
#     else:
#         return HttpResponse('Invalid Request')
def process_url(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        start_time = time.time()  # Record the start time
        result = check_onion_url_domain(url)
        end_time = time.time()  # Record the end time
        time_taken = end_time - start_time  # Calculate the time taken
        user = request.user  # Assuming the user is logged in
        onion_url = OnionURL.objects.create(url=url, result=result, user=user)
        UserLog.objects.create(user = request.user, action = "Link Enumeration", onion_url= url, onion_result= result.split('\n'), created_at=timezone.now())
        return redirect('domain_result', onion_url_id=onion_url.id, time_taken=time_taken)
    else:
        return HttpResponse('Invalid Request')

def domain_result(request, onion_url_id, time_taken):
    onion_url = OnionURL.objects.get(pk=onion_url_id)
    user = request.user
    total_time = float(time_taken)  # Convert time_taken to float
    url_list = onion_url.result.split('\n')

    # Count the number of links generated
    num_links_generated = len(url_list)

    return render(request, 'domain_result.html', {
        'onion_url': onion_url,
        'user': user,
        'url_list': url_list,
        'total_time': total_time,
        'num_links_generated': num_links_generated,  # Pass the number of links generated to the template
    })


from django.shortcuts import render
from django.http import HttpResponse
from .models import PhishingURLClassification
from .phishing_utils import FeatureExtraction_phishing
# views.py


def phishing_check(request):
    return render(request, 'phishing_checker.html')

# def classify(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         result = FeatureExtraction_phishing(url)
#         user = request.user  # Assuming the user is logged in
#         phishing_url = PhishingURLClassification.objects.create(url=url, result=result, user=user)
#         return redirect('phishing_result', phishing_url_id=phishing_url.id)
#     else:
#         return HttpResponse('Invalid Request')
def classify(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        feature_extractor = FeatureExtraction_phishing(url)
        features = feature_extractor.getFeaturesList()
        
        # Predict the result using the trained classifier
        result = clf.predict([features])[0]

        # Map result to meaningful labels
        if result == 1:
            classification = "Safe"
        else:
            classification = "Phishing"

        user = request.user  # Assuming the user is logged in
        phishing_url = PhishingURLClassification.objects.create(url=url, result=classification, user=user)
        UserLog.objects.create(user = request.user, action = "Phishing Detection", phish_url= url, phish_result= classification, created_at=timezone.now())

        return redirect('phishing_result', phishing_url_id=phishing_url.id)
    else:
        return HttpResponse('Invalid Request')

def phishing_result(request, phishing_url_id):
    phishing_url = PhishingURLClassification.objects.get(pk=phishing_url_id)
    user = request.user
    return render(request, 'phishing_result.html', {'phishing_url': phishing_url, 'user': user})

def logoutuser(request):
        
    logout(request)
    return redirect('home')

# def phishing_check(request):
#     return render(request, 'phishing_checker.html')

# def classify(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         result = FeatureExtraction_phishing(url)
#         user = request.user  # Assuming the user is logged in
#         phishing_url = PhishingURLClassification.objects.create(url=url, result=result, user=user)
#         return redirect('phishing_result', phishing_url_id=phishing_url.id)
#     else:
#         return HttpResponse('Invalid Request')
    
# def phishing_result(request, phishing_url.id):
#     phishing_url = PhishingURLClassification.objects.get(pk=phishing_url.id)
#     user = request.user
#     return render(request, 'domain_result.html', {'phishing_url': phishing_url,'user':user})

from django.db.models.functions import Cast
from django.db.models import DateField
from datetime import datetime
from django.db.models import Q

def profile(request):
    user_logs = UserLog.objects.filter(user=request.user)
    integrated_checking_urls_count = URL.objects.filter(user=request.user).count()
    phished = URL.objects.filter(result="Phishing", user=request.user).count()
    safe = URL.objects.filter(result="Safe", user=request.user).count()
    last_login_log = UserLog.objects.filter(user=request.user).order_by('-created_at').first()
    last_login = last_login_log.created_at if last_login_log else None

    date_filter = request.GET.get('date')
    search_query = request.GET.get('search')  # Get the search query

    # Initialize variables with default values
    safe_search_count = 0
    phished_search_count = 0

    # Filter user logs based on the search query and date
    if search_query:
        user_logs = user_logs.filter(Q(action__icontains=search_query) |
                                     Q(phish_url__icontains=search_query) |
                                     Q(onion_url__icontains=search_query) |
                                     Q(url__icontains=search_query))

    if date_filter:
        try:
            selected_date = datetime.strptime(date_filter, "%Y-%m-%d").date()
            user_logs = user_logs.filter(created_at__date=selected_date)
        except ValueError:
            # Handle invalid date format
            pass

    # Preprocess onion URLs to split them into a list
    for log in user_logs:
        if log.onion_result:
            log.onion_result = log.onion_result.split(',')

    # Recalculate safe and phished counts for the searched data
    safe_search_count = user_logs.filter(result="Safe").count()
    phished_search_count = user_logs.filter(result="Phishing").count()

    context = {
        'user_logs': user_logs,
        'integrated_checking_urls_count': integrated_checking_urls_count,
        'phished': phished,
        'safe': safe,
        'last_login': last_login,
        'date_filter': date_filter,
        'search_query': search_query,
        'safe_search_count': safe_search_count,
        'phished_search_count': phished_search_count,
    }
    return render(request, 'profile.html', context)

