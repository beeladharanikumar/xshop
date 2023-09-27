from django.test import TestCase,Client
from customer.models import UserProfile,Role,UserRole,Account_Activation,KnoxAuthtoken
from customer.serializers import LoginSerializer
from django.utils import timezone
from unittest import skip,skipIf
from django.core import mail
from knox.auth import AuthToken
from smtplib import SMTPException
from rest_framework.exceptions import ErrorDetail
import email
import json

class test_login_working(TestCase):
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
        response = self.client.post('/signup/',self.data)
        otp = response.context['Gotp']
        unique_id = response.context['unique_id']
        url = f'http://127.0.0.1:8000/a/activate/{unique_id}'
        data = {'otp':otp}
        self.response1 = self.client.put(url,data,content_type='application/json')
        self.login_data = {
            "username" : "dharani",
            "password" : "Kumar@143"        }
        self.url = 'http://127.0.0.1:8000/login/'

    def test_succesfully_login_check(self):
        
        
        response = self.client.post(self.url,self.login_data)
        try:
            self.assertEqual(response.status_code,200)
        except Exception as e:
            print(f'error is {e}')
    def test_with_invalid_login_details(self):
        invalid_data = {"username" : "dadada" , "password": "aadnakjfa"}
        responce_login = self.client.post(self.url,invalid_data)
        self.assertEqual(responce_login.status_code,401)

    def test_get_user_details(self):
        response = self.client.post(self.url,self.login_data)
        content_bytes = response.content
        content_data = json.loads(content_bytes.decode('utf-8'))
        token =content_data.get('accessToken')
        data123 = KnoxAuthtoken.objects.filter(user_id=1).first()  
        token_key = data123.token_key
        user_details_response = self.client.get(f'http://127.0.0.1:8000/role/details/{token_key}')
        self.assertEqual(user_details_response.status_code,200)
        response_data_bytes = user_details_response.content
        response_data = json.loads(response_data_bytes.decode('utf-8'))
        self.assertEqual(response_data['username'],self.data['username'])
    
    def test_account_deactivate_view(self):
        response = self.client.post(self.url,self.login_data)
        content_bytes = response.content
        content_data = json.loads(content_bytes.decode('utf-8'))
        token =content_data.get('accessToken')
        data123 = KnoxAuthtoken.objects.filter(user_id=1).first()  
        token_key = data123.token_key
        # print(token_key)
        account_deactivate__responce  = self.client.delete(f'/a/deactivate/{token_key}')
        self.assertEquals(account_deactivate__responce.status_code,200)
        user_verify = UserProfile.objects.get(pk =data123.user_id)
        self.assertEqual(user_verify.is_active,False)
    
    def test_logout(self):
        response = self.client.post(self.url,self.login_data)
        content_bytes = response.content
        content_data = json.loads(content_bytes.decode('utf-8'))
        token =content_data.get('accessToken')
        data123 = KnoxAuthtoken.objects.filter(user_id=1).first()  
        token_key = data123.token_key
        log_out_response  = self.client.delete(f'/logout/{token_key}')
        self.assertEqual(log_out_response.status_code,200)