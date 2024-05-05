from django.urls import path, include
from . import views
urlpatterns = [
    path('', views.home, name = "home"),
    path('login/', views.loginpage, name = "login"),
    path('signup/', views.sign_up, name = "sign_up"),  
    path('verify_email/<slug:username>', views.verify_email, name = "verify_email"),
    path('user/', views.user_home, name = "user"),   
    path("resend-otp", views.resend_otp, name="resend-otp"),
    path('url_checker', views.input_url, name='url_checker'),
    path('results/', views.results, name='results'), 
    path('subdomain-check', views.subdomain_check, name='subdomain_check'),
    path('process_url', views.process_url, name='process_url'),
    path('domain_result/<int:onion_url_id>/<str:time_taken>/', views.domain_result, name='domain_result'),
    path('logout/', views.logoutuser, name = 'logout'),
    path('phishing-check/', views.phishing_check, name='phishing_check'),
    path('classify/', views.classify, name='classify'),
    path('phishing-result/<int:phishing_url_id>/', views.phishing_result, name='phishing_result'),
    path('profile/', views.profile, name='profile'),

]       