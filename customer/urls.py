from django.urls import path
from customer.views import( RegisterView,AccountActivateView,LoginApiView,ResendActivationView,UserRoleDetailsView,AccountDeactivateView,
                           NamesUpdateAPI,CustomerEmailView,CustomerEmailUpdateView,CustomerMobileView,UsernameUpdateAPI,UpdatePasswordAPI,ForgotPasswordView,ConfirmPasswordView
                           )
from customer import views

urlpatterns = [
    path('signup/',RegisterView.as_view(),name='Sign Up Page'),
    path('a/activate/<token>', AccountActivateView.as_view(),name='account activate'),
    path('a/reactivate/',ResendActivationView.as_view(),name='Account re-activation'),
    path('login/', LoginApiView.as_view(), name='login'),
    path('logout/<token>', views.logout_api, name='logout'),
    path('role/details/<token>', UserRoleDetailsView.as_view(), name='userroledetails'),  #<-- Newly added
    path('a/deactivate/<token>', AccountDeactivateView.as_view(),name="Account Deactivation"),
    # User FirstName and LastName Update API
    path('namesupdate/<token>', NamesUpdateAPI.as_view(), name='user details Get '),
    
    # Customer email update api
    path('emailupdate/<token>', CustomerEmailView.as_view(), name='user email update'),

     # updated email validaton with OTP
    path('useremailupdate/<token>/<act_token>', CustomerEmailUpdateView.as_view(), name='user email update verification'),
     
    # User Mobile Number update
    path('mobileupdate/<token>', CustomerMobileView.as_view(), name='User Mobile Update'),
    
    # Username Update
    path('usernameupdate/<token>',UsernameUpdateAPI.as_view(),name= 'username update api'),

    # Update Password API
    path('update/password/<token>', UpdatePasswordAPI.as_view(), name='Update Password'),
    
    # Reset / Forget Password API
    path('reset_password/', ForgotPasswordView.as_view(), name='Reset Password'),
    path('reset_password/confirm/Token=<token>', ConfirmPasswordView.as_view(), name='Reset Password Confirm'),

    ]
