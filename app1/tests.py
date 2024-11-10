from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from app1.models import OtpToken
from django.core import mail

class AuthViewsTestCase(TestCase):
    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(username='testuser', password='testpass', email='testuser@example.com')

    def test_login_success(self):
        # Test successful login
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpass'})
        self.assertRedirects(response, reverse("user"))  # Ensure redirection to user page

    def test_login_failure(self):
        # Test login with wrong credentials
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'wrongpass'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid username or password")  # Error message check

    def test_sign_up_with_valid_data(self):
        # Test sign-up with valid data
        response = self.client.post(reverse('sign_up'), {
            'username': 'newuser',
            'password1': 'newpass123',
            'password2': 'newpass123',
            'email': 'newuser@example.com'
        })
        self.assertRedirects(response, reverse('verify_email', kwargs={'username': 'newuser'}))

        # Check OTP was created
        user = User.objects.get(username='newuser')
        otp_token = OtpToken.objects.get(user=user)
        self.assertIsNotNone(otp_token)

        # Check email was sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Email Verification", mail.outbox[0].subject)

    def test_sign_up_with_existing_user(self):
        # Test sign-up with an existing username
        response = self.client.post(reverse('sign_up'), {
            'username': 'testuser',
            'password1': 'newpass123',
            'password2': 'newpass123',
            'email': 'testuser@example.com'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'username or email are already taken')
from django.test import TestCase
