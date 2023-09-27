from django.db import models
# from django.utils import timezone
import datetime
from django.contrib.auth.models import AbstractUser
# from super_admin.models import Product, variants

class UserProfile(AbstractUser):
    id = models.AutoField(primary_key=True, db_column='user_id')
    first_name = models.CharField(max_length=200, blank=True, null=True)
    last_name = models.CharField(max_length=200, blank=True, null=True)
    username = models.CharField(max_length=200,unique=True)
    mobile_number = models.PositiveBigIntegerField(unique=True, null=True)
    email = models.EmailField(unique=True, max_length=40, blank=True, null=True)
    password = models.CharField(max_length=255, blank=True, null=True)
    date_joined =models.DateTimeField(default=datetime.datetime.now())
    last_login = models.DateTimeField(auto_now=True)
    alias=models.CharField(max_length=20,unique=True, null=True)
    is_active = models.BooleanField(default=False)
    is_vendor_com_user = models.BooleanField(default=False)

    class Meta:
        db_table = 'user_profile'
        ordering = ['id']


class Role(models.Model):
    role_id =models.AutoField(primary_key=True)
    role = models.CharField(unique=True, max_length=40,blank=True, null=True)
    role_desc = models.CharField(max_length=255, null=True)

    class Meta: 
        db_table = 'role'

class UserRole(models.Model):
    role_id = models.IntegerField( db_column='role_id')
    user_id = models.IntegerField(db_column='user_id')

    class Meta:
        db_table= 'user_role'
        unique_together = (('role_id', 'user_id'))



custom_expiry_date = datetime.datetime.now()+datetime.timedelta(days=2)
class Account_Activation(models.Model):
    user = models.IntegerField(db_column='user_id', null=True)
    key = models.CharField(max_length=100, blank=True, null=True)
    otp = models.PositiveIntegerField()
    agent = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(default=datetime.datetime.now())
    expiry_date = models.DateTimeField(default=custom_expiry_date)
    email = models.CharField(max_length=50, null=True,blank=True,default='')

    class Meta:
        db_table = 'account_activation'


class KnoxAuthtoken(models.Model):
    digest = models.CharField(primary_key=True, max_length=128)
    created = models.DateTimeField()
    user = models.ForeignKey(UserProfile, models.CASCADE, null=True, blank=True, db_column='user_id')
    expiry = models.DateTimeField(blank=True, null=True)
    token_key = models.CharField(max_length=8, null=True, blank=True)

    class Meta:
        managed = False
        db_table = 'knox_authtoken'

class Reset_Password(models.Model):
    user = models.IntegerField(db_column='user_id', null=True)
    user_agent = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.CharField(max_length = 50, blank=True, null=True)
    key = models.CharField(max_length=32, blank=True, null=False, db_column='key')
    created_at = models.DateTimeField(default=datetime.datetime.now())
    class Meta:
        db_table = 'reset_password'