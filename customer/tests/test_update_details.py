from django.test import TestCase,Client
from customer.models import UserProfile,Role,UserRole,Account_Activation,KnoxAuthtoken,Reset_Password
from customer.serializers import LoginSerializer
from django.utils import timezone
from unittest import skip,skipIf
from django.core import mail
from knox.auth import AuthToken
from smtplib import SMTPException
from rest_framework.exceptions import ErrorDetail
import email
import json

class test_details_updation(TestCase):
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
        signup_response = self.client.post('/signup/',self.data)
        otp = signup_response.context['Gotp']
        unique_id = signup_response.context['unique_id']
        url = f'http://127.0.0.1:8000/a/activate/{unique_id}'
        data = {'otp':otp}
        self.response1 = self.client.put(url,data,content_type='application/json')
        self.login_data = {
            "username" : "dharani",
            "password" : "Kumar@143"        }
        self.url = 'http://127.0.0.1:8000/login/'
        login_response = self.client.post(self.url,self.login_data)
        content_bytes = login_response.content
        content_data = json.loads(content_bytes.decode('utf-8'))
        token =content_data.get('accessToken')
        self.data123 = KnoxAuthtoken.objects.filter(user_id=1).first()
        self.token_key = self.data123.token_key
    def test_name_updation(self):
        names_data = {
            "first_name" : "kumar",
            "last_name" : "dharani"
         }
        names_update_response = self.client.put(f'/namesupdate/{self.token_key}',names_data,content_type='application/json')
        self.assertEqual(names_update_response.status_code,200)
        user_data = UserProfile.objects.filter(id=1).first()
        self.assertEqual(user_data.first_name,names_data['first_name'])
        self.assertEqual(user_data.last_name,names_data['last_name'])
    
    def test_email_update(self):
        user_token_key = self.data123.token_key
        updated_email = {"email" : "beeladharanikumar22@gmail.com"}
        email_otp_responce = self.client.put(f'/emailupdate/{user_token_key}',updated_email,content_type='application/json')
        self.assertEqual(email_otp_responce.status_code,200)
        json_data = email_otp_responce.content
        responce_data = json.loads(json_data.decode('utf-8'))
        act_token = responce_data.get('emailActivationToken')
        get_otp = Account_Activation.objects.filter(key = act_token).first()
        email_update_otp = {"otp" : get_otp.otp}
        otp_validation_respoce = self.client.put(f'/useremailupdate/{user_token_key}/{act_token}',email_update_otp,content_type="application/json")
        self.assertEqual(otp_validation_respoce.status_code,200)
    
    
    def test_with_wrong_act_token(self):
        user_token_key = self.data123.token_key
        updated_email = {"email" : "beeladharanikumar22@gmail.com"}
        email_otp_responce = self.client.put(f'/emailupdate/{user_token_key}',updated_email,content_type='application/json')
        self.assertEqual(email_otp_responce.status_code,200)
        json_data = email_otp_responce.content
        responce_data = json.loads(json_data.decode('utf-8'))
        otp_validation_respoce = self.client.put(f'/useremailupdate/{user_token_key}/899741969/',12345)
        self.assertEqual(otp_validation_respoce.status_code,404)


    def test_user_mobile_update(self):
        user_token_key = self.data123.token_key
        user_data = UserProfile.objects.filter(id=1).first()
        old_mobile_number = user_data.mobile_number
        update_mobile_number = {"mobile_number" : "6303049566"}
        mobile_update_response = self.client.put(f'/mobileupdate/{user_token_key}',update_mobile_number,content_type='application/json')
        self.assertEqual(mobile_update_response.status_code,200)
        responce_message = json.loads(mobile_update_response.content.decode('utf-8'))
        self.assertEqual(responce_message.get('message'),'Mobile Number Updated Successfully ')
        self.assertNotEqual(old_mobile_number,update_mobile_number["mobile_number"])

    def test_with_wrong_number(self):
        user_token_key = self.data123.token_key
        user_data = UserProfile.objects.filter(id=1).first()
        update_mobile_number = {"mobile_number" : "630304566"}
        mobile_update_response = self.client.put(f'/mobileupdate/{user_token_key}',update_mobile_number,content_type='application/json')
        self.assertEqual(mobile_update_response.status_code,400)
        responce_message = json.loads(mobile_update_response.content.decode('utf-8'))
        self.assertEqual(responce_message.get('message'),'mobile number should be 10 digits')
    
    def test_username_updation(self):
        user_token_key = self.data123.token_key
        user_data = UserProfile.objects.filter(id=1).first()
        old_username = user_data.username
        update_username = {"username" : "dharanikumar"}
        username_update_responce = self.client.put(f'/usernameupdate/{user_token_key}',update_username,content_type="application/json")
        self.assertEqual(username_update_responce.status_code,200)
        new_user_data = UserProfile.objects.filter(id=1).first()
        new_username = new_user_data.username
        self.assertEqual(new_username,update_username["username"])
        self.assertNotEqual(old_username,new_username)

    def test_same_username_update(self):
        user_token_key = self.data123.token_key
        user_data = UserProfile.objects.filter(id=1).first()
        old_username = user_data.username
        update_username = {"username" : "dharani"}
        username_update_responce = self.client.put(f'/usernameupdate/{user_token_key}',update_username,content_type="application/json")
        self.assertEqual(username_update_responce.status_code,406)
        responce_message = json.loads(username_update_responce.content.decode('utf-8'))
        self.assertEqual(responce_message.get('message'),"Username already exists, try another ")

    
    def test_reset_password(self):
        reset_acc_email = {"email" : "beeladharanikumar@gmail.com"}
        reset_url = self.client.post('/reset_password/',reset_acc_email,content_type="application/json")
        self.assertEqual(reset_url.status_code,200)
        bytes_data = json.loads(reset_url.content.decode('utf-8'))
        self.assertEqual(bytes_data.get('message'),'Password reset email sent')
        reset_data = Reset_Password.objects.filter(id=1).first()
        reset_key = reset_data.key
        reset_passwords_data = {"password" : "Dharani@2001","confirmPassword" : "Dharani@2001"}
        reset_confirm_url = self.client.put(f'/reset_password/confirm/Token={reset_key}',reset_passwords_data,content_type="application/json")
        self.assertEqual(reset_confirm_url.status_code,200)
        reset_bytes_data = json.loads(reset_confirm_url.content.decode('utf-8'))
        self.assertEqual(reset_bytes_data.get('message'),'Password changed Successfully, Please Login')
    
    def test_reset_password_invalid_format(self):
        reset_acc_email = {"email" : "beeladharanikumakiujuiir@gmail.com"}
        reset_url = self.client.post('/reset_password/',reset_acc_email,content_type="application/json")
        self.assertEqual(reset_url.status_code,400)
        bytes_data = json.loads(reset_url.content.decode('utf-8'))
        self.assertEqual(bytes_data.get('email',{}).get('message'),'This Email is Not Registered')



        reset_acc_email = {"email" : "beeladharanikumar@gmail.com"}
        reset_url = self.client.post('/reset_password/',reset_acc_email,content_type="application/json")
        self.assertEqual(reset_url.status_code,200)
        bytes_data = json.loads(reset_url.content.decode('utf-8'))
        self.assertEqual(bytes_data.get('message'),'Password reset email sent')
        reset_data = Reset_Password.objects.filter(id=1).first()
        reset_key = reset_data.key
        reset_passwords_data = {"password" : "Dharani@2001","confirmPassword" : "Dharadadaani@2001"}
        reset_confirm_url = self.client.put(f'/reset_password/confirm/Token={reset_key}',reset_passwords_data,content_type="application/json")
        bytes_data1 = json.loads(reset_confirm_url.content.decode('utf-8'))
        self.assertEqual(bytes_data1.get('message'),"[Password Fields didn\'t Match]")
        self.assertEqual(reset_confirm_url.status_code,400)

    
    def test_update_password(self):
        user_data = UserProfile.objects.filter(id=1).first()
        old_hashed_pass = user_data.password
        password_updation_data ={
                "current_password": 
                    "Kumar@143"
                ,
                "new_password": 
                    "Kumar@123"
                ,
                "confirm_password": 
                    "Kumar@123"
                
                }
        updation_responce = self.client.put(f'/update/password/{self.token_key}',password_updation_data,content_type="application/json")
        self.assertEqual(updation_responce.status_code,200)
        user_data = UserProfile.objects.filter(id=1).first()
        new_hashed_pass = user_data.password
        self.assertNotEqual(old_hashed_pass,new_hashed_pass)


    def test_invalid_update_passwords(self):
        password_updation_data ={
                "current_password": 
                    "Dharani@143"
                ,
                "new_password": 
                    "Kumar@123"
                ,
                "confirm_password": 
                    "Kumar@123"
                
                }
        updation_responce = self.client.put(f'/update/password/{self.token_key}',password_updation_data,content_type="application/json")
        self.assertEqual(updation_responce.status_code,406)
        bytes_data = json.loads(updation_responce.content.decode('utf-8'))
        self.assertEqual(bytes_data.get('message'),"Incorrect Current Password")

        password_updation_data1 ={
                "current_password": 
                    "Kumar@143"
                ,
                "new_password": 
                    "Kumar@123"
                ,
                "confirm_password": 
                    "Kumeear@123"
                
                }
        updation_responce = self.client.put(f'/update/password/{self.token_key}',password_updation_data1,content_type="application/json")
        self.assertEqual(updation_responce.status_code,406)
        bytes_data = json.loads(updation_responce.content.decode('utf-8'))
        self.assertEqual(bytes_data.get('message'),"There was an error with your Password combination")


