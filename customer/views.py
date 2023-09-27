from rest_framework import views
from rest_framework.views import APIView
from django.db import transaction
from customer.models import UserProfile,Role,UserRole,Account_Activation,KnoxAuthtoken,Reset_Password
from customer.serializers import (RegisterSerializer,ActivateAccountSerializer,LoginSerializer,ResetActivationSerializer,UserUpdateSerializer,
                                  Useremailserializer,Userotpactivateserializer,Usermobileserializer,UsernameSerializer,ForgetPasswordSerializer,ConfirmPasswordSerializer,UpdatePasswordSerializer,
                                  )
from rest_framework.response import Response
from rest_framework import status
from django_user_agents.utils import get_user_agent
from django.utils.crypto import get_random_string
from django.template.loader import render_to_string
from django.core.mail import send_mail
import re
from rest_framework.generics import CreateAPIView
from rest_framework.decorators import api_view
from django.conf import settings
import random
from django.contrib.auth import authenticate, login as login1, logout
from knox.auth import AuthToken
from datetime import datetime
from django.contrib.auth.hashers import make_password, check_password
from pytz import utc 
###########################################################################################3
class RegisterView(views.APIView):
    serializer_class= RegisterSerializer
    @transaction.atomic()
    def post(self,request):
        serializer = self.serializer_class(data = request.data)
        if serializer.is_valid(raise_exception=True):
            u=serializer.validated_data['username']
            email = serializer.validated_data['email']
            if (UserProfile.objects.filter(username__iexact=u)):
                error ={
                    "username": ['user profile with this username already exists.']
                }
                return Response(error, status=status.HTTP_400_BAD_REQUEST)

            pwd=serializer.validated_data['password']
            pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$!%*?&])[A-Za-z\d@#$!%*?&]{8,}$"

            r= re.findall(pattern,pwd)
            if not r:
                data={
                    "message":"Password is invalid.Min 8 character. Password must contain at least :one small alphabet one capital alphabet one special character \nnumeric digit."
                }
                return Response(data,status=status.HTTP_406_NOT_ACCEPTABLE)

            # try:
            unique_id = get_random_string(length=64)
            protocol ='http://'
            # current_site = get_current_site(request).domain
            current_site = '54.67.88.195/'
            api = 'core/activate_account/'
            Gotp = random.randint(10000,99999)
            context = {'Gotp': Gotp,'api':api,'unique_id':unique_id,'protocol':protocol,'current_site':current_site}
            html_message = render_to_string('registration_email.html', context)
    
            message = 'Hello, welcome to our website!'
            subject = "Welcome to xShop: Verify your account"
            from_email = settings.EMAIL_HOST_USER
            to_email = [email.lower()]
            send_mail(subject, message, from_email, to_email, html_message=html_message)

            aliass = get_random_string(length=10)
            serializer.save()
            u = UserProfile.objects.get(email = email.lower())
            if (UserProfile.objects.filter(alias=aliass).exists()):
                aliass = get_random_string(length=10)
                UserProfile.objects.filter(email=email.lower()).update(alias=aliass)
            else:
                UserProfile.objects.filter(email=email.lower()).update(alias=aliass)
            # add email field data
            Account_Activation.objects.create(user = u.id, key = unique_id,agent = current_site,otp=Gotp)
            role = Role.objects.get(role='USER')
            r_id = role.role_id
            user_role = UserRole.objects.create(role_id = r_id, user_id = u.id)
            user_role.save()

            data = {
                "message" : "Account Activation Email Sent",
                "email" : email.lower(),
                "emailActivationToken"  : unique_id
            }
            return Response(data, status=status.HTTP_201_CREATED)
            # except :
            #     return Response({"message":"Authentication Required"},status=status.HTTP_503_SERVICE_UNAVAILABLE)
        else:
            return Response({"message" :serializer.errors},status=status.HTTP_409_CONFLICT)    

class AccountActivateView(views.APIView):
    serializer_class = ActivateAccountSerializer

    @transaction.atomic()
    def put(self, request, token):
        try:
            token = Account_Activation.objects.get(key=token)
        except:
            return Response({"message" : "Invalid Token in URL"}, status=status.HTTP_404_NOT_FOUND)
        if token.expiry_date >= token.created_at:
            serializer = ActivateAccountSerializer(data = request.data)
            if serializer.is_valid(raise_exception=True):
                u_id = token.user
                otp_valid = token.otp
                otp = serializer.data['otp']
                if otp_valid ==otp:
                    UserProfile.objects.filter(id=u_id).update(is_active='True')
                    Account_Activation.objects.filter(user = u_id).delete()
                    return Response({"message" : "Account successfully activated"},status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Incorrect OTP, Please try again"}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"message":"Enter OTP"},status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            return Response({"message" : "Activation Token/ OTP Expired"} , status=status.HTTP_401_UNAUTHORIZED)
        
class ResendActivationView(views.APIView):
    serializer_class = ResetActivationSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            mail_id = serializer.data['email']

            if UserProfile.objects.filter(email=email).exists():


                name = UserProfile.objects.get(email = mail_id)
                u_id = name.id
                Account_Activation.objects.filter(user = u_id).delete()
                unique_id = get_random_string(length=64)
                # current_site = get_current_site(request).domain
                protocol ='http://'
                current_site = '54.67.88.195/'
                api = 'core/activate_account/'

                Gotp = random.randint(10000,99999)
                context = { 'email': email,'Gotp': Gotp,'api':api,'unique_id':unique_id,'protocol':protocol,'current_site':current_site}
                html_message = render_to_string('registration_email.html', context)

                message = "Your Account Activation One-Time Password is {}\nTo activate your account, please click on the following url:\n {}{}{}{}\n".format(Gotp,protocol,current_site,api,unique_id)
                subject = "Welcome to xShop! Please Verify your email address"
                from_email = settings.EMAIL_HOST_USER
                to_email = [email]
                send_mail(subject, message, from_email, to_email,html_message=html_message)
                Account_Activation.objects.create(user = u_id, key = unique_id, otp=Gotp)
                data = {
                    "message" : "Account Activation Email Sent",
                    "email" : serializer.data['email'],
                    "emailActivationToken"  : unique_id
                }
                return Response(data, status=status.HTTP_201_CREATED)
            else:
                return Response({"message":"This Email is Not Registered"}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"message":"Missing Value"}, status=status.HTTP_401_UNAUTHORIZED)


class LoginApiView(views.APIView):
    serializer_class = LoginSerializer

    @transaction.atomic()
    def post(self, request):
        serializer = LoginSerializer(data = request.data)
        if serializer.is_valid(raise_exception=True):
            username  = serializer.data['username']
            password = serializer.data['password']
            if (UserProfile.objects.filter(username__icontains=username)) or (UserProfile.objects.filter(email=username)):
                if(UserProfile.objects.filter(username__icontains=username, is_active='True') or UserProfile.objects.filter(email__icontains=username, is_active='True')):
                    try:
                        data = UserProfile.objects.get(email__icontains=username)
                        try:
                            user = authenticate(username=data, password=password)
                            # KnoxAuthtoken.objects.filter(user=data.id).delete()
                            _, token = AuthToken.objects.create(user)
                        except:
                            return Response({"message":"Incorrect Password"}, status=status.HTTP_401_UNAUTHORIZED)
                    except:
                        data = UserProfile.objects.get(username__iexact=username)
                        try:
                            user = authenticate(username=data, password=password)
                            # KnoxAuthtoken.objects.filter(user=data.id).delete()
                            _, token = AuthToken.objects.create(user)
                        except:
                            return Response({"message":"Incorrect Password"}, status=status.HTTP_401_UNAUTHORIZED)      
                    KnoxAuthtoken.objects.filter(expiry__lte=datetime.now(utc)).delete()
                    if user is not None:
                        user1 = user.id
                        login1(request, user)
                        userrole = UserRole.objects.filter(user_id=user1).values('role_id')
                        roles_list=[] 
                        for i in userrole:
                            role = i['role_id']     
                            roles_list.append(role)
                        
                        if 3 in roles_list:
                            user_role=3
                        elif 2 in roles_list:
                            user_role=2
                        elif 1 in roles_list:
                            user_role=1
                        else:
                            user_role=4
                        data = ({
                            "accessToken":token,
                            "role_id":user_role
                        })
                        return Response(data, status=status.HTTP_200_OK)
                    else:
                        return Response({"message" : "User doesn't exixts"},status=status.HTTP_400_BAD_REQUEST)
                else:
                    data = {"message":'Account is in In-Active, please Activate your account'}
                    return Response(data, status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                data = {"message" :"Username Not Found"}
                return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"message" : "Enter Username or Password"}, status=status.HTTP_400_BAD_REQUEST)


#################################  GET User details #######################
class UserRoleDetailsView(views.APIView):

    @transaction.atomic
    def get(self,request,token):
        try:
            token1 = KnoxAuthtoken.objects.get(token_key=token)
        except:
            data = {"message" : "Invalid Access Token"}
            return Response(data, status=status.HTTP_404_NOT_FOUND)

        user = token1.user_id
        usertable = UserProfile.objects.get(id=user)
        userdata = usertable.id
        userrole = UserRole.objects.filter(user_id=userdata).values('role_id')
        for i in userrole:
            role = i['role_id']
        if(UserProfile.objects.filter(id=userdata, is_active='True')):
            if(token1.expiry < datetime.now(utc)):
                KnoxAuthtoken.objects.filter(user=user).delete()
                data = {"message":'Session Expired, Please login again'}
                return Response(data, status=status.HTTP_408_REQUEST_TIMEOUT)
            else:
                data = {
                    "username":usertable.username,
                    "mobile_number":usertable.mobile_number,
                    "email":usertable.email,
                    "first_name":usertable.first_name,
                    "last_name":usertable.last_name,
                    "is_active" : usertable.is_active,
                    "role":role
                }
                return Response(data, status=status.HTTP_200_OK)
        else:
            data = {"message":'User is in In-Active, please Activate your account'}
            return Response(data, status=status.HTTP_406_NOT_ACCEPTABLE)


class AccountDeactivateView(views.APIView):

    @transaction.atomic
    def delete(self,request,token):
        try:
            token1 = KnoxAuthtoken.objects.get(token_key=token)
        except:
            data = {"message" : "Invalid Access Token"}
            return Response(data, status=status.HTTP_404_NOT_FOUND)

        user = token1.user_id
        usertable = UserProfile.objects.get(id=user)
        userdata = usertable.id
       
        if(UserProfile.objects.filter(id=userdata, is_active='True')):
            if(token1.expiry < datetime.now(utc)):
                KnoxAuthtoken.objects.filter(user=user).delete()
                data = {"message":'Session Expired, Please login again'}
                return Response(data, status=status.HTTP_408_REQUEST_TIMEOUT)
            else:
                user= UserProfile.objects.get(id=userdata)
                UserProfile.objects.filter(id=userdata).update(is_active=False)
                # UserRole.objects.filter(user_id=userdata).delete()
                message = "Your Account is De-activated Successfully"
                subject = "Account Deactivated"
                from_email = settings.EMAIL_HOST_USER
                to_email = [user.email]
                send_mail(subject, message, from_email, to_email)
                return Response({"message":"Account deactivated Successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"message":"User is in In-Active, please Activate your account"})
        
@api_view(["DELETE"])
def logout_api(request,token):
    try:
        KnoxAuthtoken.objects.get(token_key=token).delete()
        logout(request)
        return Response({"message":"Logout Success"})
    except:
        return Response({'message':"Invalid Access Token"},status=status.HTTP_400_BAD_REQUEST)

    
##################   User First and Last Name update   ###################
class NamesUpdateAPI(CreateAPIView):
    serializer_class = UserUpdateSerializer

    @transaction.atomic
    def put(self,request,token):
        try:
            token1 = KnoxAuthtoken.objects.get(token_key=token)
        except:
            data = {"message" : "Invalid Access Token"}
            return Response(data, status=status.HTTP_404_NOT_FOUND)

        user = token1.user_id
        usertable = UserProfile.objects.get(id=user)
        userdata = usertable.id
        role = Role.objects.get(role='USER')
        role1 = role.role_id
        roles = UserRole.objects.filter(role_id=role1).filter(user_id=userdata)
        if(UserProfile.objects.filter(id=userdata, is_active='True')):
            if roles.exists():
                if token1.expiry < datetime.now(utc):
                    KnoxAuthtoken.objects.filter(user=user).delete()
                    data = {"message":'Session Expired, Please login again'}
                    return Response(data, status=status.HTTP_408_REQUEST_TIMEOUT)
                else:
                    serializer = self.get_serializer(data=request.data)
                    if serializer.is_valid(raise_exception=True):
                        firstname = serializer.validated_data['first_name']
                        lastname = serializer.validated_data['last_name']
                        if lastname=='':
                            lname = ''
                        else:
                            lname = lastname

                        UserProfile.objects.filter(id=userdata).update(first_name=firstname, last_name=lname)
                        return Response({"message":"Updated successfully"}, status=status.HTTP_200_OK)
                    else:
                        return Response(serializer.error, status=status.HTTP_400_BAD_REQUEST)
            else:
                data ={
                    "warning" : "User not assigned to Role",
                    "message" : "Activate your account"
                }
                return Response(data, status=status.HTTP_404_NOT_FOUND)
        else:
            data = {"message":'User is in In-Active, please Activate your account'}
            return Response(data, status=status.HTTP_406_NOT_ACCEPTABLE)


##################   User email update ######################
class CustomerEmailView(CreateAPIView):
    serializer_class = Useremailserializer

    @transaction.atomic
    def put(self,request,token):
        try:
            token1 = KnoxAuthtoken.objects.get(token_key=token)
        except:
            data = {
                    "message" : "Invalid Access Token"
                }
            return Response(data, status=status.HTTP_404_NOT_FOUND)

        roles = Role.objects.get(role='USER')
        userrole = roles.role_id
        user = token1.user_id
        usertable = UserProfile.objects.get(id=user)
        userdata = usertable.id
        table1 = UserProfile.objects.filter(id=userdata, is_active='True')
        if(UserRole.objects.filter(role_id=userrole, user_id=userdata)):
            if table1.exists():
                if(token1.expiry < datetime.now(utc)):
                    KnoxAuthtoken.objects.filter(user=user).delete()
                    data = {"message":'Session Expired, Please login again'}
                    return Response(data, status=status.HTTP_408_REQUEST_TIMEOUT)
                else:
                    serializer = self.get_serializer(usertable, data=request.data)
                    if serializer.is_valid(raise_exception=True):
                        serializerdata = serializer.validated_data['email']
                        if(UserProfile.objects.filter(email=serializerdata).exists()):
                            return Response({"message":"Email already exists, try another "}, status=status.HTTP_406_NOT_ACCEPTABLE)
                        else:
                            Account_Activation.objects.filter(email=serializerdata).delete()
                            unique_id = get_random_string(length=64)
                            # current_site = get_current_site(request).domain
                            protocol ='http://'
                            current_site = '54.67.88.195/'
                            api = 'core/activate_account/'
                            Gotp = random.randint(10000,99999)
                            message = "Hi {},\n\n Request For Email Update.\nYour One-Time Password is {}\nTo Change your Email, please click on the following url:\n {}{}{}{}\n".format(usertable.username,Gotp,protocol,current_site,api,unique_id)
                            subject = "xShop Account Activation"
                            from_email = settings.EMAIL_HOST_USER
                            to_email = [serializerdata]
                            send_mail(subject, message, from_email, to_email)
                            Account_Activation.objects.create(user = userdata, key = unique_id, otp=Gotp, email=serializerdata)

                            data = {
                                "message" : "Requested for Email Update", 
                                "emailActivationToken": unique_id
                                }
                            return Response(data, status=status.HTTP_200_OK)
                    else:
                        return Response(serializer.error, status=status.HTTP_400_BAD_REQUEST)
            else:
                data = {"message" : "Account is in In-Active, please Activate your account"}
                return Response(data, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"message" : "User not assigned to Role",}, status=status.HTTP_406_NOT_ACCEPTABLE)


#################   User email update Verification   #############
class CustomerEmailUpdateView(CreateAPIView):
    serializer_class = Userotpactivateserializer

    @transaction.atomic
    def put(self,request,token,act_token):
        try:
            token1 = KnoxAuthtoken.objects.get(token_key=token)
        except:
            data = {"message" : "Invalid Access Token"}
            return Response(data, status=status.HTTP_404_NOT_FOUND)
        
        try:
            token = Account_Activation.objects.get(key=act_token)
        except:
            data = {"message" : "Invalid verification Token"}
            return Response(data, status=status.HTTP_404_NOT_FOUND)

        roles = Role.objects.get(role='USER')
        userrole = roles.role_id
        user = token1.user_id
        usertable = UserProfile.objects.get(id=user)
        userdata = usertable.id
        table1 = UserProfile.objects.filter(id=userdata, is_active='True')
        if(UserRole.objects.filter(role_id=userrole, user_id=userdata)):
            if table1.exists():
                if(token1.expiry < datetime.now(utc)):
                    KnoxAuthtoken.objects.filter(user=user).delete()
                    data = {"message":'Session Expired, Please login again'}
                    return Response(data, status=status.HTTP_408_REQUEST_TIMEOUT)
                else:
                    serializer = self.get_serializer(usertable, data=request.data)
                    if serializer.is_valid(raise_exception=True):
                        u_id = token.user
                        otp_valid = token.otp
                        otp = serializer.validated_data['otp']
                        if otp_valid ==otp:
                            UserProfile.objects.filter(id=u_id).update(email=token.email)
                            Account_Activation.objects.filter(user = u_id).delete()
                            return Response({"message" : "Email Updated Successfully"},status=status.HTTP_200_OK)
                        else:
                            return Response({"message": "Incorrect OTP, Please try again"}, status=status.HTTP_401_UNAUTHORIZED)
                    else:
                        return Response(serializer.error, status=status.HTTP_400_BAD_REQUEST)
            else:
                data = {"message" : "Account is in In-Active, please Activate your account"}
                return Response(data, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"message" : "User not assigned to Role",}, status=status.HTTP_406_NOT_ACCEPTABLE)


##################   User mobile update ######################
class CustomerMobileView(CreateAPIView):
    serializer_class = Usermobileserializer

    @transaction.atomic
    def put(self,request,token):
        try:
            token1 = KnoxAuthtoken.objects.get(token_key=token)
        except:
            data = {
                    "message" : "Invalid Access Token"
                }
            return Response(data, status=status.HTTP_404_NOT_FOUND)

        roles = Role.objects.get(role='USER')
        userrole = roles.role_id
        user = token1.user_id
        usertable = UserProfile.objects.get(id=user)
        userdata = usertable.id
        table1 = UserProfile.objects.filter(id=userdata, is_active='True')
        if(UserRole.objects.filter(role_id=userrole, user_id=userdata)):
            if table1.exists():
                if(token1.expiry < datetime.now(utc)):
                    KnoxAuthtoken.objects.filter(user=user).delete()
                    data = {"message":'Session Expired, Please login again'}
                    return Response(data, status=status.HTTP_408_REQUEST_TIMEOUT)
                else:
                    serializer = self.get_serializer(usertable, data=request.data)
                    if serializer.is_valid(raise_exception=True):
                        serializerdata = serializer.validated_data['mobile_number']
                        if(UserProfile.objects.filter(mobile_number=serializerdata).exists()):
                            return Response({"message":"Mobile Number already exists"}, status=status.HTTP_406_NOT_ACCEPTABLE)
                        else:
                            if len(str(serializerdata)) <10 or len(str(serializerdata)) >10:
                                return Response({"message":"mobile number should be 10 digits"}, status=status.HTTP_400_BAD_REQUEST)
                            else:
                                UserProfile.objects.filter(id=userdata).update(mobile_number=serializerdata)
                                data = {
                                    "message":"Mobile Number Updated Successfully "
                                    }
                                return Response(data, status=status.HTTP_200_OK)
                    else:
                        return Response(serializer.error, status=status.HTTP_400_BAD_REQUEST)
            else:
                data = {"message" : "Account is in In-Active, please Activate your account"}
                return Response(data, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"message" : "User not assigned to Role",}, status=status.HTTP_406_NOT_ACCEPTABLE)


########################## Customer Username Update API
class UsernameUpdateAPI(CreateAPIView):
    serializer_class = UsernameSerializer

    @transaction.atomic
    def put(self,request,token):
        try:
            token1 = KnoxAuthtoken.objects.get(token_key=token)
        except:
            data = {
                    "message" : "Invalid Access Token"
                }
            return Response(data, status=status.HTTP_404_NOT_FOUND)

        roles = Role.objects.get(role='USER')
        userrole = roles.role_id
        user = token1.user_id
        usertable = UserProfile.objects.get(id=user)
        userdata = usertable.id
        table1 = UserProfile.objects.filter(id=userdata, is_active='True')
        if(UserRole.objects.filter(role_id=userrole, user_id=userdata)):
            if table1.exists():
                if(token1.expiry < datetime.now(utc)):
                    KnoxAuthtoken.objects.filter(user=user).delete()
                    data = {"message":'Session Expired, Please login again'}
                    return Response(data, status=status.HTTP_408_REQUEST_TIMEOUT)
                else:
                    serializer = self.get_serializer(usertable, data=request.data)
                    if serializer.is_valid(raise_exception=True):
                        serializerdata = serializer.validated_data['username']
                        if(UserProfile.objects.filter(username=serializerdata).exists()):
                            return Response({"message":"Username already exists, try another "}, status=status.HTTP_406_NOT_ACCEPTABLE)
                        else:
                            UserProfile.objects.filter(id=userdata).update(username=serializerdata)
                            data = {
                                "message":"Username Updated Successfully "
                                }
                            return Response(data, status=status.HTTP_200_OK)
                    else:
                        return Response(serializer.error, status=status.HTTP_400_BAD_REQUEST)
            else:
                data = {"message" : "Account is in In-Active, please Activate your account"}
                return Response(data, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"message" : "User not assigned to Role",}, status=status.HTTP_406_NOT_ACCEPTABLE)

class ForgotPasswordView(APIView):
    serializer_class = ForgetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data['email']
            mail_id = serializer.data['email']

            name = UserProfile.objects.get(email = mail_id)
            u_id = name.id
            Reset_Password.objects.filter(user=u_id).delete()

            unique_id = get_random_string(length=32)
            # current_site = get_current_site(request).domain
            current_site = '54.67.88.195/'
            protocol ='http://'
            interface = get_user_agent(request)
            Reset_Password.objects.create(user = u_id, key=unique_id, ip_address=current_site, user_agent=interface)
            subject = "xShop Reset Password Assistance"
            api = '/core/reset/password/'
            context = {'username':name.username,'api':api,'unique_id':unique_id,'protocol':protocol,'current_site':current_site}
            html_message = render_to_string('registration_email.html', context)

            send_mail(
                subject = subject,
                message = "Hi {}, \n\nThere was a request to change your password! \n\nIf you did not make this request then please ignore this email. \n\nYour password reset link \n {}{}{}{}".format(name.username,protocol,current_site, api, unique_id),
                from_email = settings.EMAIL_HOST_USER,
                recipient_list=[email],
                html_message=html_message
            )
            return Response({"message" : "Password reset email sent"})
        else:
            return Response (serializer.error, status=status.HTTP_401_UNAUTHORIZED)


class ConfirmPasswordView(APIView):
    serializer_class = ConfirmPasswordSerializer

    def put(self, request, token):
        try:
            token = Reset_Password.objects.get(key=token)
        except:
            return Response({"message":"Token Doesn't Exists"},status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(data = request.data)
        if serializer.is_valid(raise_exception=True):
            
            name = token.user
            use = UserProfile.objects.get(id =name)
            # pwd = serializer.data['password']

            pwd=serializer.validated_data['password']
            pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$!%*?&])[A-Za-z\d@#$!%*?&]{8,}$"

            r= re.findall(pattern,pwd)
            if not r:
                data={
                    "message":"Password is invalid.Min 8 character. Password must contain at least :one small alphabet one capital alphabet one special character \nnumeric digit."
                }
                return Response(data,status=status.HTTP_406_NOT_ACCEPTABLE)

            UserProfile.objects.filter(id = name).update(password=make_password(pwd))
            Reset_Password.objects.filter(user=use.id).delete()
            return Response({"message" : "Password changed Successfully, Please Login"}, status=status.HTTP_200_OK)
        else:
            return Response({"message":"Password Fields didn't Match"}, status=status.HTTP_400_BAD_REQUEST)

#########################################################################################
# Update/Change Password 
class UpdatePasswordAPI(CreateAPIView):
    serializer_class = UpdatePasswordSerializer

    @transaction.atomic
    def put(self,request,token):
        try:
            token1 = KnoxAuthtoken.objects.get(token_key=token)
        except:
            data = {"message" : "Invalid Access Token"}
            return Response(data, status=status.HTTP_404_NOT_FOUND)
        user = token1.user_id
        usertable = UserProfile.objects.get(id=user)
        userdata = usertable.id
        role = Role.objects.get(role='USER')
        role1 = role.role_id
        roles = UserRole.objects.filter(role_id=role1,user_id=userdata)
        if roles.exists():
            if token1.expiry < datetime.now(utc):
                    KnoxAuthtoken.objects.filter(user=user).delete()
                    data = {"message":'Session Expired, Please login again'}
                    return Response(data, status=status.HTTP_408_REQUEST_TIMEOUT)
            else:
                serializer = self.get_serializer(data = request.data)
                if serializer.is_valid(raise_exception=True):
                    current_pwd = serializer.validated_data['current_password']
                    new_pwd = serializer.validated_data['new_password']
                    confirm_pwd = serializer.validated_data['confirm_password']
                    
                    pwd=serializer.validated_data['new_password']
                    pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$!%*?&])[A-Za-z\d@#$!%*?&]{8,}$"

                    r= re.findall(pattern,pwd)
                    if not r:
                        data={
                            "message":"Password is invalid.Min 8 character. Password must contain at least :one small alphabet one capital alphabet one special character \nnumeric digit."
                        }
                        return Response(data,status=status.HTTP_406_NOT_ACCEPTABLE)

                    if check_password(current_pwd, usertable.password):
                        if len(new_pwd) <8 or len(confirm_pwd)<8:
                             return Response({"message":"Check Password Length"}, status=status.HTTP_400_BAD_REQUEST)
                        else:
                            if new_pwd==confirm_pwd:
                                UserProfile.objects.filter(id=usertable.id).update(password=make_password(new_pwd))
                                return Response({"message":"Successfully Changed Your Password"}, status=status.HTTP_200_OK)
                            else:
                                return Response({"message":"There was an error with your Password combination"}, status=status.HTTP_406_NOT_ACCEPTABLE)                        
                    else:
                        return Response({"message":"Incorrect Current Password"}, status=status.HTTP_406_NOT_ACCEPTABLE)
                else:
                    return Response({"message":"Missing Field Values"}, status=status.HTTP_204_NO_CONTENT)

