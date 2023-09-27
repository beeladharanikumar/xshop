from django.test import TestCase,Client
from customer.models import UserProfile,Role,Account_Activation,UserRole
from customer.serializers import RegisterSerializer,ActivateAccountSerializer
from django.utils import timezone
from unittest import skip,skipIf
from django.core import mail
from rest_framework.exceptions import ErrorDetail
import email
import json

class test_register(TestCase):
    def setUp(self):
        self.client = Client() 
        Role.objects.create(role_id=1,role='USER',role_desc="NULL")
        self.data = {
            "username":"dharani",
            "password": "Kumar@143",
            "email": "beeladharanikumar@gmail.com",
            "first_name":"dharani",
            "last_name": "kumar",
            "mobile_number":"6303049533"
        }

    def test_register_model(self):
        # checking data is crctly recorded or not
        
        response = self.client.post('/signup/',self.data)  
        self.assertEqual(response.status_code,201)

    def test_email_check(self):
        data = {
             "username":"dharani",
            "password": "Kumar@143",
            "email": "kgdfluorsadlufjdsa@gmail.com",
            "first_name":"dharani",
            "last_name": "kumar",
            "mobile_number":"6303049533"
    }
        response = self.client.post('/signup/',data)
        self.assertEqual(response.status_code,201)
        self.assertEqual(mail.outbox[0].body,'Hello, welcome to our website!')
        self.assertEqual(response.data.get('message'),'Account Activation Email Sent')
        # print(response.data)
        # print(mail.outbox)
    
    def test_duplicate_user_email_number(self):
        data = {
             "username":"dharani",
            "password": "Kumar@143",
            "email": "kgdfluorsadlufjdsa@gmail.com",
            "first_name":"dharani",
            "last_name": "kumar",
            "mobile_number":"6303049533"
    }
        response = self.client.post('/signup/',data)
        response1 = self.client.post('/signup/',data)
        self.assertEqual(response.data.get('message'),'Account Activation Email Sent')
        self.assertEqual(response1.status_code,400)
        self.assertEqual(response1.data.get('username'),[ErrorDetail(string='user profile with this username already exists.', code='unique')])
        self.assertEqual(response1.data.get('email'),[ErrorDetail(string='Email Id already Exists', code='unique')])
        self.assertEqual(response1.data.get('mobile_number'),[ErrorDetail(string='user profile with this mobile number already exists.', code='unique')])
        # print(response.data.get('email'))

    def test_password(self):
        
        response = self.client.post('/signup/',self.data)
        if response.status_code==406:
            self.assertEqual(response.data.get('message'),'Password is invalid.Min 8 character. Password must contain at least :one small alphabet one capital alphabet one special character \nnumeric digit.')
        
    def test_account_otp(self):
        data = {
            "username":"dharani",
            "password": "Kumar@143",
            "email": "beeladharanikumar@gmail.com",
            "first_name":"dharani",
            "last_name": "kumar",
            "mobile_number":"6303049533"
        }
        response = self.client.post('/signup/',data)
        otp = response.context['Gotp']
        unique_id = response.context['unique_id']
        b=Account_Activation.objects.get()
        data = {'otp':otp}
        dup_unique_id = unique_id + 'jhii'
        url1 = f'http://127.0.0.1:8000/a/activate/{dup_unique_id}'
        dup_response = self.client.put(url1,data,content_type='application/json')
        self.assertEqual(dup_response.status_code,404)
        response_bytes = dup_response.content
        response_data = json.loads(response_bytes.decode('utf-8'))
        self.assertEqual(response_data.get('message'),'Invalid Token in URL')
        url = f'http://127.0.0.1:8000/a/activate/{unique_id}'
        if b.expiry_date>=b.created_at:
            response1 = self.client.put(url,data,content_type='application/json')
            # print(response1.status_code) 
        self.assertEqual(response1.status_code,200)
        a = UserProfile.objects.get()
        self.assertEqual(a.is_active,True)
        # to check the view of partivular url
        view_data =response1.resolver_match.func.view_class
        self.assertEqual(view_data.__name__,'AccountActivateView')
        
    def test_otp_resend(self):
        data = {
            "username":"dharani",
            "password": "Kumar@143",
            "email": "beeladharanikumar@gmail.com",
            "first_name":"dharani",
            "last_name": "kumar",
            "mobile_number":"6303049533"
        }
        response = self.client.post('/signup/',data)
        otp = response.context['Gotp']
        unique_id = response.context['unique_id']
        otp_1 = {'otp':otp}
        reactivate_url =f'http://127.0.0.1:8000/a/reactivate/'
        reactivate_wrong_data = {"email": "beeladharanikuma1213r@gmail.com"}
        responce1 = self.client.post(reactivate_url,reactivate_wrong_data,content_type='application/json')
        self.assertEqual(responce1.status_code,401)
        
        
        reactivate_data = {"email":"beeladharanikumar@gmail.com"}
        responce2 = self.client.post(reactivate_url,reactivate_data,content_type='application/json')
        new_unique_id = responce2.context["unique_id"]
        self.assertNotEqual(unique_id,new_unique_id)
        account_activate_url = f'http://127.0.0.1:8000/a/activate/{new_unique_id}'
        new_otp = responce2.context['Gotp']
        new_otp_1 = {'otp':new_otp}
        b=UserProfile.objects.get()
        self.assertEqual(b.is_active,False)
        responce2 = self.client.put(account_activate_url,new_otp_1,content_type='application/json')
        response_bytes = responce2.content
        response_data = json.loads(response_bytes.decode('utf-8'))
        self.assertEqual(response_data.get('message'),'Account successfully activated')
        b_new=UserProfile.objects.get()
        self.assertEqual(b_new.is_active,True)
        







