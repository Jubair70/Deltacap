from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.db.models import Count,Q
from django.http import (
    HttpResponseRedirect, HttpResponse)
from django.shortcuts import render_to_response, get_object_or_404
from django.template import RequestContext,loader
from django.contrib.auth.models import User
from datetime import date, timedelta, datetime
from django.utils import timezone

# from django.utils import simplejson
import json
import logging
import sys
from django.core.urlresolvers import reverse

from django.core.mail import send_mail, BadHeaderError
import smtplib


# Create your views here.
from django.db import (IntegrityError,transaction)
from django.db.models import ProtectedError
from django.shortcuts import redirect
from onadata.apps.main.models.user_profile import UserProfile
from onadata.apps.usermodule.forms import UserForm, UserProfileForm, ChangePasswordForm, UserEditForm,OrganizationForm,OrganizationDataAccessForm,ResetPasswordForm
from onadata.apps.usermodule.models import UserModuleProfile, UserPasswordHistory, UserFailedLogin,Organizations,OrganizationDataAccess

from django.contrib.auth.decorators import login_required, user_passes_test
from django import forms
# Menu imports
from onadata.apps.usermodule.forms import MenuForm
from onadata.apps.usermodule.models import MenuItem
# Unicef Imports
from onadata.apps.logger.models import Instance,XForm
# Organization Roles Import
from onadata.apps.usermodule.models import OrganizationRole,MenuRoleMap,UserRoleMap
from onadata.apps.usermodule.forms import OrganizationRoleForm,RoleMenuMapForm,UserRoleMapForm,UserRoleMapfForm
from django.forms.models import inlineformset_factory,modelformset_factory
from django.forms.formsets import formset_factory

from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.db import connection


from collections import OrderedDict
import decimal




def admin_check(user):
    current_user = UserModuleProfile.objects.filter(user=user)
    if current_user:
        current_user = current_user[0]
    else:
        return True    
    return current_user.admin


def index(request):
    current_user = request.user
    user = UserModuleProfile.objects.filter(user_id=current_user.id)
    admin = False
    if user:
        admin = user[0].admin
    if current_user.is_superuser:
        users = UserModuleProfile.objects.all().order_by("user__username")
        admin = True
        # json_posts = json.dumps(list(users.values('id','user__username' ,'organisation_name__organization','user__email')))
    elif admin:
        org_id_list = get_organization_by_user(request.user)
        users = UserModuleProfile.objects.filter(organisation_name__in=org_id_list).order_by("user__username")
        # json_posts = json.dumps(list(users))
        admin = True
    else:
        users = user
        admin = False
    template = loader.get_template('usermodule/index.html')
    context = RequestContext(request, {
            'users': users,
            'admin': admin,
            # 'json_posts' : json_posts
        })
    return HttpResponse(template.render(context))


@login_required
@user_passes_test(admin_check,login_url='/')
def register(request):
    # Like before, get the request's context.
    context = RequestContext(request)
    admin_check = UserModuleProfile.objects.filter(user=request.user)

    if request.user.is_superuser:
        admin_check = True
    elif admin_check:
        admin_check = admin_check[0].admin
    # A boolean value for telling the template whether the registration was successful.
    # Set to False initially. Code changes value to True when registration succeeds.
    registered = False
    
    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        # Attempt to grab information from the raw form information.
        # Note that we make use of both UserForm and UserProfileForm.
        user_form = UserForm(data=request.POST)
        profile_form = UserProfileForm(data=request.POST,admin_check=admin_check)

        # If the two forms are valid...
        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save()

       ## ********** Assing username and passward before Encryption  (Start)********

            usermail = user.username
            userpassword = user.password

       ## ********** Assing username and passward before Encryption (End )********

            
            form_bool = request.POST.get("admin", "xxx")
            if form_bool == "xxx":
                form_bool_value = False
            else:
                form_bool_value = True
            
            #encrypted password is saved so that it can be saved in password history table
            encrypted_password = make_password(user.password)
            user.password = encrypted_password
            user.save()

            # Now sort out the UserProfile instance.
            # Since we need to set the user attribute ourselves, we set commit=False.
            # This delays saving the model until we're ready to avoid integrity problems.
            profile = profile_form.save(commit=False)
            # profile.organisation_name = request.POST.get("organisation_name", "-1")
            profile.user = user


            expiry_months_delta = 3

            # Date representing the next expiry date
            #next_expiry_date = (datetime.today() + timedelta(expiry_months_delta*365/12))  // previously used
            next_expiry_date = datetime.today()


            profile.expired = next_expiry_date
            profile.admin = form_bool_value
            # Did the user provide a profile picture?
            # If so, we need to get it from the input form and put it in the UserProfile model.
            # if 'picture' in request.FILES:
            #     profile.picture = request.FILES['picture']

            # Now we save the UserProfile model instance.
            profile.save()

            # kobo main/models/UserProfile
            main_user_profile = UserProfile(user = user)
            main_user_profile.save()

            # Update our variable to tell the template registration was successful.
            registered = True

            #insert password into password history
            passwordHistory = UserPasswordHistory(user_id = user.id,date = datetime.now())
            passwordHistory.password = encrypted_password
            passwordHistory.save()



            ## Sending notification mail ----------- (Start) // we have imported (from django.core.mail import send_mail)

            loggeusername=request.user.username
            currentOwner = get_object_or_404(User, username__iexact=loggeusername)
            sendermail = currentOwner.email
            receivermail = user.email

            send_mail(
                'User LogIn Information',
                'Hi,\nPlease use the below information to use the Deltacap Portal.\n\nLink : http://deltacap.mpower-social.com:5001\nUserName : ' +usermail+'\nPassword :'+userpassword+'\n',
                'deltacap8@gmail.com',
                [receivermail],
                fail_silently=False,
            )

            ## Sending notification mail ----------- (End)




            messages.success(request, '<i class="fa fa-check-circle"></i> New User has been registered successfully .. </br><i class="fa fa-check-circle"></i>  A notification mail is sent to user email .. </br> <i class="fa fa-check-circle"></i> Please check mail ..',
                             extra_tags='alert-success crop-both-side')
            return HttpResponseRedirect('/usermodule/')

        # Invalid form or forms - mistakes or something else?
        # Print problems to the terminal.
        # They'll also be shown to the user.
        else:
            print user_form.errors, profile_form.errors
            # profile_form = UserProfileForm(admin_check=admin_check)

    # Not a HTTP POST, so we render our form using two ModelForm instances.
    # These forms will be blank, ready for user input.
    else:
        user_form = UserForm()
        # get request users org and the orgs he can see then pass it to model choice field
        org_id_list = get_organization_by_user(request.user)
        # org id list is not available for superuser's like kobo
        if not org_id_list:
            UserProfileForm.base_fields['organisation_name'] = forms.ModelChoiceField(queryset=Organizations.objects.all(),empty_label="Select a Organization")
        else:
            UserProfileForm.base_fields['organisation_name'] = forms.ModelChoiceField(queryset=Organizations.objects.filter(pk__in=org_id_list)
,empty_label="Select a Organization")
        profile_form = UserProfileForm(admin_check=admin_check)

    # Render the template depending on the context.
    return render_to_response(
            'usermodule/register.html',
            {'user_form': user_form, 'profile_form': profile_form, 'registered': registered},
            context)


def get_organization_by_user(user):
    org_id_list = []
    current_user = UserModuleProfile.objects.filter(user_id=user.id)
    if current_user:
        current_user = current_user[0]
        all_organizations = get_recursive_organization_children(current_user.organisation_name,[])
        org_id_list = [org.pk for org in all_organizations]
    return org_id_list


# must pass an empty organization_list initally otherwise produces bug.
def get_recursive_organization_children(organization,organization_list=[]):
    organization_list.append(organization)
    observables = Organizations.objects.filter(parent_organization = organization)
    for org in observables:
        if org not in organization_list:
            organization_list = list((set(get_recursive_organization_children(org,organization_list))))
    return list(set(organization_list))


@login_required
@user_passes_test(admin_check,login_url='/')
def organization_index(request):
    context = RequestContext(request)
    all_organizations = []
    if request.user.is_superuser:
        all_organizations = Organizations.objects.all()
    else:
        current_user = UserModuleProfile.objects.filter(user_id=request.user.id)
        if current_user:
            current_user = current_user[0]
        all_organizations = get_recursive_organization_children(current_user.organisation_name,[])
        all_organizations.remove(current_user.organisation_name)
    message = ""
    alert = ""
    org_del_message = request.GET.get('org_del_message')
    org_del_message2 = request.GET.get('org_del_message2')
    return render_to_response(
            'usermodule/organization_list.html',
            {'all_organizations':all_organizations,"message":message,"alert":alert,
            'org_del_message':org_del_message,'org_del_message2':org_del_message2,
            },
            context)


@login_required
@user_passes_test(admin_check,login_url='/')
def add_organization(request):
    # Like before, get the request's context.
    context = RequestContext(request)
    all_organizations = []
    if request.user.is_superuser:
        all_organizations = Organizations.objects.all()
        OrganizationForm.base_fields['parent_organization'] = forms.ModelChoiceField(queryset=all_organizations,empty_label="Select a Organization",required=False)
    else:
        current_user = UserModuleProfile.objects.filter(user_id=request.user.id)
        if current_user:
            current_user = current_user[0]
        all_organizations = get_recursive_organization_children(current_user.organisation_name,[])
        org_id_list = [org.pk for org in all_organizations]
        # org_id_list = list(set(org_id_list))
        OrganizationForm.base_fields['parent_organization'] = forms.ModelChoiceField(queryset=Organizations.objects.filter(pk__in=org_id_list),empty_label="Select a Parent Organization")
    # A boolean value for telling the template whether the registration was successful.
    # Set to False initially. Code changes value to True when registration succeeds.
    is_added_organization = False
    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        organization_form = OrganizationForm(data=request.POST)
        if organization_form.is_valid():
            organization_form.save()
            is_added_organization = True
            messages.success(request, '<i class="fa fa-check-circle"></i> New Organization has been added successfully!',
                             extra_tags='alert-success crop-both-side')
            return HttpResponseRedirect('/usermodule/organizations/')
        else:
            print organization_form.errors
            return render_to_response(
            'usermodule/add_organization.html',
            {'all_organizations':all_organizations,'organization_form': organization_form,'is_added_organization': is_added_organization},
            context)
    else:
        organization_form =  OrganizationForm()
    # Render the template depending on the context.
        return render_to_response(
            'usermodule/add_organization.html',
            {'all_organizations':all_organizations,'organization_form': organization_form,'is_added_organization': is_added_organization},
            context)


@login_required
@user_passes_test(admin_check,login_url='/')
def edit_organization(request,org_id):
    context = RequestContext(request)
    edited = False
    organization = get_object_or_404(Organizations, id=org_id)
    all_organizations = []
    if request.user.is_superuser:
        all_organizations = Organizations.objects.filter(~Q(id = organization.pk))
        OrganizationForm.base_fields['parent_organization'] = forms.ModelChoiceField(queryset=all_organizations,empty_label="Select a Organization",required=False)
    else:
        current_user = UserModuleProfile.objects.filter(user_id=request.user.id)
        if current_user:
            current_user = current_user[0]
        all_organizations = get_recursive_organization_children(current_user.organisation_name,[])
        org_id_list = [org.pk for org in all_organizations]
        org_id_list.remove(organization.pk)
        OrganizationForm.base_fields['parent_organization'] = forms.ModelChoiceField(queryset=Organizations.objects.filter(pk__in=org_id_list),empty_label="Select a Parent Organization")
    
    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        organization_form = OrganizationForm(data=request.POST,instance=organization)
        if organization_form.is_valid():
            organization_form.save()
            edited = True
            messages.success(request,
                             '<i class="fa fa-check-circle"></i> Organization has been updated successfully!',
                             extra_tags='alert-success crop-both-side')
            return HttpResponseRedirect('/usermodule/organizations/')
        else:
            print organization_form.errors
            return render_to_response(
            'usermodule/edit_organization.html',
            {'org_id':org_id,'organization_form': organization_form, 'edited': edited},
            context)
        # Not a HTTP POST, so we render our form using two ModelForm instances.
        # These forms will be blank, ready for user input.
    else:
        organization_form = OrganizationForm(instance=organization)
    return render_to_response(
            'usermodule/edit_organization.html',
            {'org_id':org_id,'organization_form': organization_form, 'edited': edited},
            context)


@login_required
@user_passes_test(admin_check,login_url='/')
def delete_organization(request,org_id):
    context = RequestContext(request)
    org = Organizations.objects.get(pk = org_id)
    try:
        org.delete()
        messages.success(request,
                         '<i class="fa fa-check-circle"></i> Organization has been deleted successfully!',
                         extra_tags='alert-success crop-both-side')
    except ProtectedError:
        org_del_message = """User(s) are assigned to this organization,
        please delete those users or assign them a different organization
        before deleting this organization"""

        org_del_message2 = """Or, This Organization may be parent of 
        one or more organization(s), Change their parent to some other organization."""
        
        return HttpResponseRedirect('/usermodule/organizations/?org_del_message='+org_del_message+"&org_del_message2="+org_del_message2)
    return HttpResponseRedirect('/usermodule/organizations/')


# @login_required
# @user_passes_test(lambda u: u.is_superuser,login_url='/')
# def organization_mapping(request):
#     # Like before, get the request's context.
#     context = RequestContext(request)
#     mapped_organizations = OrganizationDataAccess.objects.all()
#     all_organizations = Organizations.objects.all()
#     has_added_mapping = False

#     # If it's a HTTP POST, we're interested in processing form data.
#     if request.method == 'POST':
#         organization_data_access_form = OrganizationDataAccessForm(data=request.POST)
#         # If the two forms are valid...
#         if organization_data_access_form.is_valid():
#             try:
#                 organization_access_map = organization_data_access_form.save();
#                 organization_access_map.observer_oraganization = request.POST.get("observer_oraganization", "-1")
#                 organization_access_map.observable_oraganization = request.POST.get("observable_oraganization", "-1")
#                 organization_access_map.save()
#                 has_added_mapping = True
#             except IntegrityError as e:
#                 transaction.rollback()
#                 message = "That entry already exists"                
#                 return render_to_response(
#             'usermodule/add_organization_access.html',
#             {'mapped_organizations':mapped_organizations,'all_organizations':all_organizations,"message":message,
#             'organization_data_access_form': organization_data_access_form,'has_added_mapping': has_added_mapping},
#             context)
#         else:
#             print organization_data_access_form.errors
#     # Not a HTTP POST, so we render our form using two ModelForm instances.
#     # These forms will be blank, ready for user input.
#     else:
#         organization_data_access_form =  OrganizationDataAccessForm()
    
#     # Render the template depending on the context.
#     return render_to_response(
#             'usermodule/add_organization_access.html',
#             {'mapped_organizations':mapped_organizations,'all_organizations':all_organizations,'organization_data_access_form': organization_data_access_form,'has_added_mapping': has_added_mapping},
#             context)


@login_required
@user_passes_test(admin_check,login_url='/')
def organization_access_list(request):
    param_user_id = request.POST['id']
    response_data = []
    observer = get_object_or_404(Organizations, id=param_user_id)
    all_organizations = get_recursive_organization_children(observer,[])
    for org in all_organizations:
        data = {}
        data["observer"] = observer.organization
        data["observable"] = org.organization
        response_data.append(data)
    return HttpResponse(json.dumps(response_data), content_type="application/json")

 
# @login_required
# @user_passes_test(admin_check,login_url='/')
# def delete_organization_mapping(request,org_id):
#     mappings = OrganizationDataAccess.objects.filter(id = org_id)
#     mappings.delete()
#     return HttpResponseRedirect('/usermodule/organizations/')


# def get_organization_name(organizations,id):
#     for arra in organizations:
#         if int(arra.id) == int(id):
#             return arra.oraganization
#     return None


@login_required
def edit_profile(request,user_id):
	context = RequestContext(request)
	edited = False
	user = get_object_or_404(User, id=user_id)
	profile = get_object_or_404(UserModuleProfile, user_id=user_id)
        admin_check = UserModuleProfile.objects.filter(user=request.user)
        if request.user.is_superuser:
            admin_check = True
        elif admin_check:
            admin_check = admin_check[0].admin
    # If it's a HTTP POST, we're interested in processing form data.
        if request.method == 'POST':
            # Attempt to grab information from the raw form information.
            # Note that we make use of both UserForm and UserProfileForm.
            user_form = UserEditForm(data=request.POST,instance=user,user=request.user)
            profile_form = UserProfileForm(data=request.POST,instance=profile,admin_check=admin_check)
            # If the two forms are valid...
            if user_form.is_valid() and profile_form.is_valid():
                edited_user = user_form.save(commit=False);
                # password_new = request.POST['password']
                # if password_new:
                #     edited_user.set_password(password_new)
                edited_user.save()
                form_bool = request.POST.get("admin", "xxx")
                if form_bool == "xxx":
                    form_bool_value = False
                else:
                    form_bool_value = True
                # Now sort out the UserProfile instance.
                # Since we need to set the user attribute ourselves, we set commit=False.
                # This delays saving the model until we're ready to avoid integrity problems.
                profile = profile_form.save(commit=False)
                # profile.organisation_name = request.POST.get("organisation_name", "-1")
                # profile.admin = request.POST.get("admin", "False")
                profile.user = edited_user
                profile.admin = form_bool_value
                # Did the user provide a profile picture?
                # If so, we need to get it from the input form and put it in the UserProfile model.
                # if 'picture' in request.FILES:
                #     profile.picture = request.FILES['picture']

                # Now we save the UserProfile model instance.
                profile.save()

                # Update our variable to tell the template registration was successful.
                edited = True
                messages.success(request, '<i class="fa fa-check-circle"></i> User profile has been updated successfully!', extra_tags='alert-success crop-both-side')
                return HttpResponseRedirect('/usermodule/')

            # Invalid form or forms - mistakes or something else?
            # Print problems to the terminal.
            # They'll also be shown to the user.
            else:
                # profile_form = UserProfileForm(admin_check=admin_check)
                print user_form.errors, profile_form.errors

        # Not a HTTP POST, so we render our form using two ModelForm instances.
        # These forms will be blank, ready for user input.
        else:
            user_form = UserEditForm(instance=user,user=request.user)
            org_id_list = get_organization_by_user(request.user)
            if not org_id_list:
                UserProfileForm.base_fields['organisation_name'] = forms.ModelChoiceField(queryset=Organizations.objects.all(),empty_label="Select a Organization")
            else:
                UserProfileForm.base_fields['organisation_name'] = forms.ModelChoiceField(queryset=Organizations.objects.filter(pk__in=org_id_list)
    ,empty_label="Select a Organization")
            profile_form = UserProfileForm(instance = profile,admin_check=admin_check)

        return render_to_response(
                'usermodule/edit_user.html',
                {'id':user_id, 'user_form': user_form, 'profile_form': profile_form, 'edited': edited},
                context)


@login_required
@user_passes_test(admin_check,login_url='/')
def delete_user(request,user_id):
    context = RequestContext(request)
    user = User.objects.get(pk = user_id)
    # deletes the user from both user and rango
    user.delete()
    messages.success(request, '<i class="fa fa-check-circle"></i> This user has been deleted successfully!',
                     extra_tags='alert-success crop-both-side')
    return HttpResponseRedirect('/usermodule/')


def change_password(request):
    context = RequestContext(request)
    if request.GET.get('userid'):
        edit_user = get_object_or_404(User, pk = request.GET.get('userid')) 
        logged_in_user = edit_user.username
        change_password_form = ChangePasswordForm(logged_in_user=logged_in_user)
    else:
        change_password_form = ChangePasswordForm()
    # change_password_form = ChangePasswordForm()
    # Take the user back to the homepage.
    if request.method == 'POST':
        # expiry_months_delta: password change after how many months
        expiry_months_delta = 60
        # Date representing the next expiry date
        next_expiry_date = (datetime.today() + timedelta(expiry_months_delta*365/12))

        # Attempt to grab information from the raw form information.
        # Note that we make use of both UserForm and UserProfileForm.
        change_password_form = ChangePasswordForm(data=request.POST)
        username = request.POST['username']
        old_password = request.POST['old_password']
        new_password = request.POST['new_password']
        current_user = authenticate(username=username, password=old_password)

        loggeusername = request.user.username

        if username == loggeusername:

            if change_password_form.is_valid() and current_user is not None:
                """ current user is authenticated and also new password
                 is available so change the password and redirect to
                 home page with notification to user """
                encrypted_password = make_password(new_password)
                current_user.password = encrypted_password
                current_user.save()

                passwordHistory = UserPasswordHistory(user_id = current_user.id,date = datetime.now())
                passwordHistory.password = encrypted_password
                passwordHistory.save()

                profile = get_object_or_404(UserModuleProfile, user_id=current_user.id)
                profile.expired = next_expiry_date
                profile.save()
                login(request,current_user)
                #return HttpResponseRedirect('/usermodule/')   // Previously Used
                return HttpResponseRedirect('/')

                # else:
                    #     return HttpResponse('changed your own password buddy')
                    # return HttpResponse( (datetime.now()+ timedelta(days=30)) )
            else:
                return render_to_response(
                        'usermodule/change_password.html',
                        {'change_password_form': change_password_form,'invalid':True},
                        context)
        else:

            messages.success(request, '<i class="fa fa-check-circle"></i> User can change only own password !!',
                             extra_tags='alert-success crop-both-side')
            return render_to_response(
                'usermodule/change_password.html',
                {'change_password_form': change_password_form, 'invalid': True},
                context)



    return render_to_response(
                'usermodule/change_password.html',
                {'change_password_form': change_password_form},
                context)

@login_required
@user_passes_test(admin_check,login_url='/')
def reset_password(request,reset_user_id):
    context = RequestContext(request)
    reset_password_form = ResetPasswordForm()
    reset_user = get_object_or_404(User, pk=reset_user_id)
    reset_user_profile = get_object_or_404(UserModuleProfile,user=reset_user)
    if request.method == 'POST':
        # expiry_months_delta: password change after how many months
        expiry_months_delta = 60
        # Date representing the next expiry date
        next_expiry_date = (datetime.today() + timedelta(expiry_months_delta*365/12))

        # Attempt to grab information from the raw form information.
        # Note that we make use of both UserForm and UserProfileForm.
        reset_password_form = ResetPasswordForm(data=request.POST)
        
        if reset_password_form.is_valid() and reset_user is not None:
            """ current user is authenticated and also new password
             is available so change the password and redirect to
             home page with notification to user """
            encrypted_password = make_password(request.POST['new_password'])
            reset_user.password = encrypted_password
            reset_user.save()


            ## Sending notification mail ----------- (Start) // we have imported (from django.core.mail import send_mail)

            usermail = reset_user.username
            userpassword = request.POST['new_password']
            receivermail = reset_user.email


            print "############################################"
            print usermail
            print userpassword
            print receivermail

            send_mail(
                'User LogIn Information',
                'Hi,\nPlease use the below information to use the Deltacap Portal.\n\nLink : http://deltacap.mpower-social.com:5001\nUserName : ' +usermail+'\nPassword :'+userpassword+'\n',
                'deltacap8@gmail.com',
                [receivermail],
                fail_silently=False,
            )

            ## Sending notification mail ----------- (End)





            passwordHistory = UserPasswordHistory(user_id = reset_user.id,date = datetime.now())
            passwordHistory.password = encrypted_password
            passwordHistory.save()

            reset_user_profile.expired = next_expiry_date
            reset_user_profile.save()









            messages.success(request, '<i class="fa fa-check-circle"></i> Your password has been updated successfully!',
                             extra_tags='alert-success crop-both-side')
            return HttpResponseRedirect('/usermodule/')
        else:
            return render_to_response(
                    'usermodule/reset_password.html',
                    {'reset_user':reset_user,'reset_password_form': reset_password_form,'invalid':True , 'id':reset_user_id},
                    context)

    return render_to_response(
                'usermodule/reset_password.html',
                {'reset_password_form': reset_password_form,
                'reset_user':reset_user,'id':reset_user_id,
                },
                context)


def user_login(request):
    # Like before, obtain the context for the user's request.
    context = RequestContext(request)
    logger = logging.getLogger(__name__)
    # If the request is a HTTP POST, try to pull out the relevant information.
    if request.method == 'POST':
        # Gather the username and password provided by the user.
        # This information is obtained from the login form.
        username = request.POST['username']
        password = request.POST['password']

        # Use Django's machinery to attempt to see if the username/password
        # combination is valid - a User object is returned if it is.
        user = authenticate(username=username, password=password)

        # If we have a User object, the details are correct.
        # If None (Python's way of representing the absence of a value), no user
        # with matching credentials was found.
        if user:
            # number of login attempts allowed
            max_allowed_attempts = 5
            # count of invalid logins in db
            counter_login_attempts = UserFailedLogin.objects.filter(user_id=user.id).count()
            # check for number of allowed logins if it crosses limit do not login.
            if counter_login_attempts > max_allowed_attempts:
                return HttpResponse("Your account is locked for multiple invalid logins, contact admin to unlock")

            # Is the account active? It could have been disabled.
            if user.is_active:
                if hasattr(user, 'usermoduleprofile'):
                    current_user = user.usermoduleprofile

                   # if date.today() > current_user.expired.date():
                    if timezone.now() > current_user.expired:
                        return HttpResponseRedirect('/usermodule/change-password')
                login(request, user)
                UserFailedLogin.objects.filter(user_id=user.id).delete()
                return HttpResponseRedirect(request.POST['redirect_url'])
            else:
                # An inactive account was used - no logging in!
                # return HttpResponse("Your User account is disabled.")
                return error_page(request,"Your User account is disabled")
        else:
            # Bad login details were provided. So we c an't log the user in.
            # try:
            #     attempted_user_id = User.objects.get(username=username).pk
            # except User.DoesNotExist:
            #     return HttpResponse("Invalid login details supplied when login attempted.")
            # UserFailedLogin(user_id = attempted_user_id).save()
            # print "Invalid login details: {0}, {1}".format(username, password)
            # return HttpResponse("Invalid login details supplied.")
            return error_page(request,"Invalid login details supplied")

    # The request is not a HTTP POST, so display the login form.
    # This scenario would most likely be a HTTP GET.
    else:
        if request.GET.get('next'):
            print request.GET.get('next')
            redirect_url = request.GET.get('next')
        else:
            redirect_url = '/'
        # No context variables to pass to the template system, hence the
        # blank dictionary object...
        return render_to_response('usermodule/login.html', {'redirect_url':redirect_url}, context)


@login_required
@user_passes_test(admin_check,login_url='/')
def locked_users(request):
    # Since we know the user is logged in, we can now just log them out.
    current_user = request.user
    users = []
    message = ''
    max_failed_login_attempts = 5

    user = UserModuleProfile.objects.filter(user_id=current_user.id)
    admin = False
    if user:
        admin = user[0].admin

    if current_user.is_superuser or admin:
        failed_logins = UserFailedLogin.objects.all().values('user_id').annotate(total=Count('user_id')).order_by('user_id')
        for f_login in failed_logins:
            if f_login['total'] > max_failed_login_attempts:
                user = UserModuleProfile.objects.filter(user_id=f_login['user_id'])[0]
                users.append(user)
    else:
        return HttpResponseRedirect("/usermodule/")
    if not users:
        message = "All the user accounts are unlocked"

    # Take the user back to the homepage.
    template = loader.get_template('usermodule/locked_users.html')
    context = RequestContext(request, {
            'users': users,
            'message':message
        })
    return HttpResponse(template.render(context))


@login_required
def unlock(request):
    param_user_id = request.POST['id']
    current_user = request.user
    response_data = {}
    
    user = UserModuleProfile.objects.filter(user_id=current_user.id)
    admin = False
    if user:
        admin = user[0].admin

    if current_user.is_superuser or admin:
        UserFailedLogin.objects.filter(user_id=param_user_id).delete()
        response_data['message'] = 'User unlocked'
    else:
        response_data['message'] = 'You are not authorized to unlock'

    return HttpResponse(json.dumps(response_data), content_type="application/json")


@login_required
def user_logout(request):
    # Since we know the user is logged in, we can now just log them out.
    logout(request)
    # Take the user back to the homepage.
    return HttpResponseRedirect('/login/')


# =======================================================================================
@login_required
@user_passes_test(admin_check,login_url='/')
def add_menu(request):
    context = RequestContext(request)
    all_menu = MenuItem.objects.all()
    # A boolean value for telling the template whether the registration was successful.
    # Set to False initially. Code changes value to True when registration succeeds.
    is_added_menu = False

    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        menu_form = MenuForm(data=request.POST)
        # If the two forms are valid...
        if menu_form.is_valid():
            menu =menu_form.save()
            menu.save()
            is_added_menu = True
        else:
            print menu_form.errors

    # Not a HTTP POST, so we render our form using two ModelForm instances.
    # These forms will be blank, ready for user input.
        return HttpResponseRedirect('/usermodule/menu-list/')
    else:
        menu_form = MenuForm()
    
    # Render the template depending on the context.
        return render_to_response(
            'usermodule/add_menu.html',
            {'all_menu':all_menu,'menu_form': menu_form,
            'is_added_menu': is_added_menu},
            context)


@login_required
@user_passes_test(admin_check,login_url='/')
def menu_index(request):
    context = RequestContext(request)
    all_menu = MenuItem.objects.all().order_by("sort_order")
    return render_to_response(
            'usermodule/menu_list.html',
            {'all_menu':all_menu},
            context)


@login_required
@user_passes_test(admin_check,login_url='/')
def edit_menu(request,menu_id):
    context = RequestContext(request)
    edited = False
    menu = get_object_or_404(MenuItem, id=menu_id)
    
    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        # Attempt to grab information from the raw form information.
        # Note that we make use of both UserForm and UserProfileForm.
        menu_form = MenuForm(data=request.POST,instance=menu)
        
        # If the two forms are valid...
        if menu_form.is_valid():
            edited_user = menu_form.save(commit=False);
            edited_user.save()
            edited = True
            return HttpResponseRedirect('/usermodule/menu-list')
        else:
            print menu_form.errors

    # Not a HTTP POST, so we render our form using two ModelForm instances.
    # These forms will be blank, ready for user input.
    else:
        menu_form = MenuForm(instance=menu)

    return render_to_response(
            'usermodule/edit_menu.html',
            {'id':menu_id, 'menu_form': menu_form,
            'edited': edited},
            context)


@login_required
@user_passes_test(admin_check,login_url='/')
def delete_menu(request,menu_id):
    context = RequestContext(request)
    menu = MenuItem.objects.get(pk = menu_id)
    # deletes the user from both user and rango
    menu.delete()
    return HttpResponseRedirect('/usermodule/menu-list')


# =========================================================
# Roles based on Organization CRUD
@login_required
@user_passes_test(admin_check,login_url='/')
def add_role(request):
    context = RequestContext(request)
    # A boolean value for telling the template whether the registration was successful.
    # Set to False initially. Code changes value to True when registration succeeds.
    is_added_role = False

    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        role_form = OrganizationRoleForm(data=request.POST)
        print role_form
        # If the two forms are valid...
        if role_form.is_valid():
            role_form.save()
            is_added_role = True
        else:
            print role_form.errors

    # Not a HTTP POST, so we render our form using two ModelForm instances.
    # These forms will be blank, ready for user input.
        messages.success(request, '<i class="fa fa-check-circle"></i> New role has been added successfully!',
                         extra_tags='alert-success crop-both-side')
        return HttpResponseRedirect('/usermodule/roles-list/')
    else:
        if request.user.is_superuser:
            OrganizationRoleForm.base_fields['organization'] = forms.ModelChoiceField(queryset=Organizations.objects.all(),empty_label="Select a Organization")
            role_form = OrganizationRoleForm()
        else:
            org_id_list = get_organization_by_user(request.user)
            OrganizationRoleForm.base_fields['organization'] = forms.ModelChoiceField(queryset=Organizations.objects.filter(pk__in=org_id_list),empty_label="Select a Organization")
            role_form = OrganizationRoleForm()
    # Render the template depending on the context.
        return render_to_response(
            'usermodule/add_role.html',
            {'role_form': role_form,
            'is_added_role': is_added_role},
            context)


@login_required
@user_passes_test(admin_check,login_url='/')
def roles_index(request):
    context = RequestContext(request)
    # filter orgs based on logged in user
    if request.user.is_superuser:
        all_roles = OrganizationRole.objects.all().order_by("organization")
    else:
        user = get_object_or_404(UserModuleProfile, user=request.user)
        all_roles = OrganizationRole.objects.filter(organization = user.organisation_name)
    return render_to_response(
            'usermodule/roles_list.html',
            {'all_roles':all_roles},
            context)


@login_required
@user_passes_test(admin_check, login_url='/')
def edit_role(request, role_id):
    context = RequestContext(request)
    edited = False
    role = get_object_or_404(OrganizationRole, id=role_id)
    if request.method == 'POST':
        role_form = OrganizationRoleForm(data=request.POST,instance=role)
        if role_form.is_valid():
            role_form.save()
            edited = True
            messages.success(request, '<i class="fa fa-check-circle"></i> This role has been edited successfully!',
                             extra_tags='alert-success crop-both-side')
            return HttpResponseRedirect('/usermodule/roles-list')
        else:
            print role_form.errors
    else:
        if request.user.is_superuser:
            OrganizationRoleForm.base_fields['organization'] = forms.ModelChoiceField(queryset=Organizations.objects.all(),empty_label="Select a Organization")
            
        else:
            org_id_list = get_organization_by_user(request.user)
            OrganizationRoleForm.base_fields['organization'] = forms.ModelChoiceField(queryset=Organizations.objects.filter(pk__in=org_id_list),empty_label="Select a Organization")
        role_form = OrganizationRoleForm(instance=role,initial = {'organization': role.organization,'role': role.role })    
        # role_form = OrganizationRoleForm(instance=role)
    return render_to_response(
            'usermodule/edit_role.html',
            {'id':role_id, 'role_form': role_form,
            'edited': edited},
            context)


@login_required
@user_passes_test(admin_check,login_url='/')
def delete_role(request,role_id):
    context = RequestContext(request)
    role = OrganizationRole.objects.get(pk = role_id)
    # deletes the user from both user and rango
    role.delete()
    messages.success(request, '<i class="fa fa-check-circle"></i> This role has been deleted successfully!',
                     extra_tags='alert-success crop-both-side')
    return HttpResponseRedirect('/usermodule/roles-list')


# =========================================================
@login_required
@user_passes_test(admin_check,login_url='/')
def role_menu_map_index(request):
    context = RequestContext(request)
    insertList = []
    menu_dict = {}
    # filter orgs based on logged in user
    if request.method == 'POST':
        new_menu = request.POST.getlist('menu_id')
        print new_menu
        for val in new_menu:
            splitVal = val.split("__")
            instance = MenuRoleMap(role_id=splitVal[0], menu_id=splitVal[1])
            insertList.append(instance)

        MenuRoleMap.objects.all().delete()
        MenuRoleMap.objects.bulk_create(insertList)
        messages.success(request, '<i class="fa fa-check-circle"></i> Access List has been updated successfully!',
                         extra_tags='alert-success crop-both-side')
        return HttpResponseRedirect('/usermodule/role-menu-map-list/')
    else:
        if request.user.is_superuser:
            menu_items = MenuItem.objects.all()
            roles = OrganizationRole.objects.all()
            for role in roles:
                org_menu_list = MenuRoleMap.objects.filter(role=role.id).values_list('menu_id', flat=True)
                menu_dict[role.id] = org_menu_list
        else:
            menu_items = MenuItem.objects.all()
           #roles = OrganizationRole.objects.all()  // Previously Used

           ## ******  Logged User can Access Own and child Role / Access / controll ******* (Start)

            current_user = UserModuleProfile.objects.filter(user_id=request.user.id)
            if current_user:
                current_user = current_user[0]
            all_organizations = get_recursive_organization_children(current_user.organisation_name, [])
            org_id_list = [org.pk for org in all_organizations]
            roles = OrganizationRole.objects.filter(organization__in=org_id_list)

          ## ******  Logged User can Access Own and child Role / Access / controll ******* (End)

            for role in roles:
                org_menu_list = MenuRoleMap.objects.filter(role = role.id).values_list('menu_id', flat=True)
                menu_dict[role.id] = org_menu_list

        return render_to_response(
            'usermodule/roles_menu_map_list.html',
            {'menu_items':menu_items, 'menu_dict':menu_dict,'roles':roles},
            context)


# Roles based on Organization CRUD
@login_required
@user_passes_test(admin_check,login_url='/')
def add_role_menu_map(request):
    context = RequestContext(request)
    is_added_role = False
    if request.method == 'POST':
        role_form = RoleMenuMapForm(data=request.POST)
        if role_form.is_valid():
            role_form.save()
            is_added_role = True
            messages.success(request, '<i class="fa fa-check-circle"></i> New access has been added successfully!',
                             extra_tags='alert-success crop-both-side')
            return HttpResponseRedirect('/usermodule/role-menu-map-list/')
        else:
            print role_form.errors
        return HttpResponseRedirect('/usermodule/role-menu-map-list/')
    else:
        if request.user.is_superuser:
            RoleMenuMapForm.base_fields['role'] = forms.ModelChoiceField(queryset=OrganizationRole.objects.all().order_by("organization"),empty_label="Select a Organization Role")
            
        else:
            org_id_list = get_organization_by_user(request.user)
            RoleMenuMapForm.base_fields['role'] = forms.ModelChoiceField(queryset=OrganizationRole.objects.filter(organization__in=org_id_list).order_by("organization"),empty_label="Select a Organization Role")
        role_form = RoleMenuMapForm()
        return render_to_response(
            'usermodule/add_role_menu_map.html',
            {'role_form': role_form,
            'is_added_role': is_added_role},
            context)


@login_required
@user_passes_test(admin_check, login_url='/')
def edit_role_menu_map(request, item_id):
    context = RequestContext(request)
    edited = False
    role_menu_map = get_object_or_404(MenuRoleMap, id=item_id)
    if request.method == 'POST':
        role_form = RoleMenuMapForm(data=request.POST,instance=role_menu_map)
        if role_form.is_valid():
            role_form.save()
            edited = True
            messages.success(request, '<i class="fa fa-check-circle"></i> This access has been edit successfully!',
                             extra_tags='alert-success crop-both-side')
            return HttpResponseRedirect('/usermodule/role-menu-map-list/')
        else:
            print role_form.errors
    else:
        if request.user.is_superuser:
            RoleMenuMapForm.base_fields['role'] = forms.ModelChoiceField(queryset=OrganizationRole.objects.all(),empty_label="Select a Organization Role")
        else:
            org_id_list = get_organization_by_user(request.user)
            RoleMenuMapForm.base_fields['role'] = forms.ModelChoiceField(queryset=OrganizationRole.objects.filter(organization__in=org_id_list),empty_label="Select a Organization Role")
        role_form = RoleMenuMapForm(instance=role_menu_map,initial = {'role': role_menu_map.role,'menu': role_menu_map.menu })
    return render_to_response(
            'usermodule/edit_role_menu_map.html',
            {'id':item_id, 'role_form': role_form,
            'edited': edited},
            context)


@login_required
@user_passes_test(admin_check, login_url='/')
def delete_role_menu_map(request, item_id):
    context = RequestContext(request)
    del_map_item = MenuRoleMap.objects.get(pk = item_id)
    del_map_item.delete()
    messages.success(request, '<i class="fa fa-check-circle"></i> This access has been deleted successfully!',
                     extra_tags='alert-success crop-both-side')
    return HttpResponseRedirect('/usermodule/role-menu-map-list')


# =========================================================
@login_required
@user_passes_test(admin_check, login_url='/')
def organization_roles(request):
    context = RequestContext(request)
    if request.user.is_superuser:
        all_organizations = Organizations.objects.all()
    else:    
        org_id_list = get_organization_by_user(request.user)
        all_organizations = Organizations.objects.filter(pk__in=org_id_list)
    message = None
    if len(all_organizations) == 0:    
        message = "You do not have any Organizations under your supervision."
    return render_to_response(
            'usermodule/organization_roles.html',
            {'all_organizations':all_organizations,"message":message},
            context)


@login_required
@user_passes_test(admin_check, login_url='/')
def user_role_map(request, org_id=None):
    context = RequestContext(request)
    edited = False
    roles = OrganizationRole.objects.filter(organization=org_id)
    users = UserModuleProfile.objects.filter(organisation_name=org_id)
    message = None
    if len(roles) == 0 or len(users) == 0:    
        message = "Your organization must have atleast one user and one role before assignment."
    return render_to_response(
            'usermodule/user_role_map.html',
            {'id':org_id,
            'users' : users,
            'roles' : roles,
            'message':message,
            'edited': edited},
            context)


@login_required
@user_passes_test(admin_check, login_url='/')
def adjust_user_role_map(request, org_id=None):
    context = RequestContext(request)
    is_added = False
    roles = OrganizationRole.objects.filter(organization=org_id)
    users = UserModuleProfile.objects.filter(organisation_name=org_id)
    initial_list = []
    for user_item in users:
        alist = UserRoleMap.objects.filter(user=user_item.pk).values('role')
        mist = []
        for i in alist:
            mist.append( i['role'])
        initial_list.append({'user': user_item.pk,'role':mist,'username': user_item.user.username})

    UserRoleMapfForm.base_fields['role'] = forms.ModelChoiceField(queryset=roles,empty_label=None)
    PermisssionFormSet = formset_factory(UserRoleMapfForm,max_num=len(users))
    new_formset = PermisssionFormSet(initial=initial_list)
    
    if request.method == 'POST':
        new_formset = PermisssionFormSet(data=request.POST)
        for idx,user_role_form in enumerate(new_formset):
            # user_role_form = UserRoleMapfForm(data=request.POST)
            u_id = request.POST['form-'+str(idx)+'-user']
            mist = initial_list[idx]['role']
            current_user = UserModuleProfile.objects.get(pk=u_id)
            results = map(int, request.POST.getlist('role-'+str(idx+1)))
            deleter = list(set(mist) - set(results))
            for role_id in results:
                roley = OrganizationRole.objects.get(pk=role_id)
                try:
                    UserRoleMap.objects.get(user=current_user,role=roley)
                except ObjectDoesNotExist as e:
                    UserRoleMap(user=current_user,role=roley).save()
            for dely in deleter:
                loly = OrganizationRole.objects.get(pk=dely)
                ob = UserRoleMap.objects.get(user=current_user,role=loly).delete()
        messages.success(request, '<i class="fa fa-check-circle"></i> Organization Roles have been adjusted successfully!',
                         extra_tags='alert-success crop-both-side')
        return HttpResponseRedirect('/usermodule/user-role-map/'+org_id)
    
    return render_to_response(
            'usermodule/add_user_role_map.html',
            {
            'id':org_id,
            # 'formset':formset,
            'new_formset':new_formset,
            'roles':roles,
            # 'users':users,
            },
            context)


def error_page(request,message = None):
    context = RequestContext(request)
    if not message:    
        message = "Something went wrong"
    return render_to_response(
            'usermodule/error_404.html',
            {'message':message,
            },
            context)

@csrf_exempt
@login_required
def sent_datalist(request,username):
    context = RequestContext(request)
    content_user = get_object_or_404(User, username__iexact=str(username))
    print content_user
    json_data_response = []
    #print content_user.id
    cursor = connection.cursor()
    options_query ='SELECT title, logger_instance.date_created,logger_instance.uuid  FROM logger_instance,logger_xform where logger_instance.xform_id=logger_xform.id and logger_instance.user_id='+ str(content_user.id)
    #print options_query
    cursor.execute(options_query)
    tmp_db_value = cursor.fetchall()
    if tmp_db_value is not None:
        for every in tmp_db_value:
            instance_data_json = {}
            instance_data_json['xform_id'] = str(every[0])
            instance_data_json['date_created'] = str(every[1])
            instance_data_json['uuid'] = str(every[2])
            json_data_response.append(instance_data_json)
    cursor.close()
    return HttpResponse(json.dumps(json_data_response))




"""
@Emtious
For Dash Board 'Male & Female Priority'
"""


def getTrainingData(request):

    queryMostPriorityTrainingMale = "with t as(SELECT rank_training_need_delta_manage_plannig,rank_training_need_long_term_development_plan,rank_training_need_assessment_framework,rank_training_need_investment_plan,rank_training_need_realization_realization_bulding_infrastructu,rank_training_need_opearation_opearation,rank_training_need_water_governance,rank_training_need_mga_negotiation_group_decision,rank_training_need_water_resource_management,rank_training_need_river_training,rank_training_need_urban_water_system,rank_training_need_agriculture_food_security,rank_training_need_coastal_zone_management,rank_training_need_environmental_assessment,rank_training_need_programme_management FROM deltacap_meal where gender like '1')," \
                                "t1 as(SELECT 'Socio Economic Development' category,rank_training_need_delta_manage_plannig rnk FROM t where rank_training_need_delta_manage_plannig='3' union all " \
                                "SELECT 'Long-term Strategy Development' category,rank_training_need_long_term_development_plan rnk FROM t where rank_training_need_long_term_development_plan='3' union all " \
                                "SELECT 'Strategy Assessment' category,rank_training_need_assessment_framework rnk FROM t where rank_training_need_assessment_framework='3' union all " \
                                "SELECT 'Investment Planning' category,rank_training_need_investment_plan rnk FROM t where rank_training_need_investment_plan='3' union all " \
                                "SELECT 'Building Infrastructure' category,rank_training_need_realization_realization_bulding_infrastructu rnk FROM t where rank_training_need_realization_realization_bulding_infrastructu='3' union all " \
                                "SELECT 'Operation & Maintenance Infrastructure' category,rank_training_need_opearation_opearation rnk FROM t where rank_training_need_opearation_opearation='3' union all " \
                                "SELECT 'Water Governance' category,rank_training_need_water_governance rnk FROM t  where rank_training_need_water_governance='3' union all " \
                                "SELECT 'Mutual Gains Approach' category,rank_training_need_mga_negotiation_group_decision rnk FROM t where rank_training_need_mga_negotiation_group_decision='3' union all " \
                                "SELECT 'Water Resouce Management' category,rank_training_need_water_resource_management rnk FROM t where rank_training_need_water_resource_management='3' union all " \
                                "SELECT 'River Training and Morphology' category,rank_training_need_river_training rnk FROM t where rank_training_need_river_training='3' union all " \
                                "SELECT 'Urban Water System & Sanitation' category,rank_training_need_urban_water_system rnk FROM t where rank_training_need_urban_water_system='3' union all " \
                                "SELECT 'Agriculture' category,rank_training_need_agriculture_food_security rnk FROM t where rank_training_need_agriculture_food_security='3' union all " \
                                "SELECT 'Coastal Zone & Estuaries Management' category,rank_training_need_coastal_zone_management rnk FROM t where rank_training_need_coastal_zone_management='3' union all " \
                                "SELECT 'Environmental Assessment' category,rank_training_need_environmental_assessment rnk FROM t where rank_training_need_environmental_assessment='3' union all " \
                                "SELECT 'Programme Management' category,rank_training_need_programme_management rnk FROM t where rank_training_need_programme_management='3')" \
                                " select category,count(*) cnt from t1 group by category"


    queryMostPriorityTrainingFemale = "with t as(SELECT rank_training_need_delta_manage_plannig,rank_training_need_long_term_development_plan,rank_training_need_assessment_framework,rank_training_need_investment_plan,rank_training_need_realization_realization_bulding_infrastructu,rank_training_need_opearation_opearation,rank_training_need_water_governance,rank_training_need_mga_negotiation_group_decision,rank_training_need_water_resource_management,rank_training_need_river_training,rank_training_need_urban_water_system,rank_training_need_agriculture_food_security,rank_training_need_coastal_zone_management,rank_training_need_environmental_assessment,rank_training_need_programme_management FROM deltacap_meal where gender like '2' )," \
                                "t1 as(SELECT 'Socio Economic Development' category,rank_training_need_delta_manage_plannig rnk FROM t where rank_training_need_delta_manage_plannig='3' union all " \
                                "SELECT 'Long-term Strategy Development' category,rank_training_need_long_term_development_plan rnk FROM t where rank_training_need_long_term_development_plan='3' union all " \
                                "SELECT 'Strategy Assessment' category,rank_training_need_assessment_framework rnk FROM t where rank_training_need_assessment_framework='3' union all " \
                                "SELECT 'Investment Planning' category,rank_training_need_investment_plan rnk FROM t where rank_training_need_investment_plan='3' union all " \
                                "SELECT 'Building Infrastructure' category,rank_training_need_realization_realization_bulding_infrastructu rnk FROM t where rank_training_need_realization_realization_bulding_infrastructu='3' union all " \
                                "SELECT 'Operation & Maintenance Infrastructure' category,rank_training_need_opearation_opearation rnk FROM t where rank_training_need_opearation_opearation='3' union all " \
                                "SELECT 'Water Governance' category,rank_training_need_water_governance rnk FROM t  where rank_training_need_water_governance='3' union all " \
                                "SELECT 'Mutual Gains Approach' category,rank_training_need_mga_negotiation_group_decision rnk FROM t where rank_training_need_mga_negotiation_group_decision='3' union all " \
                                "SELECT 'Water Resouce Management' category,rank_training_need_water_resource_management rnk FROM t where rank_training_need_water_resource_management='3' union all " \
                                "SELECT 'River Training and Morphology' category,rank_training_need_river_training rnk FROM t where rank_training_need_river_training='3' union all " \
                                "SELECT 'Urban Water System & Sanitation' category,rank_training_need_urban_water_system rnk FROM t where rank_training_need_urban_water_system='3' union all " \
                                "SELECT 'Agriculture' category,rank_training_need_agriculture_food_security rnk FROM t where rank_training_need_agriculture_food_security='3' union all " \
                                "SELECT 'Coastal Zone & Estuaries Management' category,rank_training_need_coastal_zone_management rnk FROM t where rank_training_need_coastal_zone_management='3' union all " \
                                "SELECT 'Environmental Assessment' category,rank_training_need_environmental_assessment rnk FROM t where rank_training_need_environmental_assessment='3' union all " \
                                "SELECT 'Programme Management' category,rank_training_need_programme_management rnk FROM t where rank_training_need_programme_management='3')" \
                                " select category,count(*) cnt from t1 group by category"

    dataSetMostPriorityTrainingMale = getJsonDataForTraining(queryMostPriorityTrainingMale , 'category')
    dataSetMostPriorityTrainingFemale = getJsonDataForTraining(queryMostPriorityTrainingFemale, 'category')





    jsonDataSetAll = json.dumps({
        'dataSetMostPriorityTrainingMale':dataSetMostPriorityTrainingMale,
        'dataSetMostPriorityTrainingFemale': dataSetMostPriorityTrainingFemale,
        }, default=decimal_date_default)

    return HttpResponse(jsonDataSetAll, mimetype='text/json')


def getJsonDataForTraining(query , category_field):

    dataset = __db_fetch_values_dict(query)

    ## ******  ( Category for multiple value of each Legend) ******* (Start)

    '''
        uniqueList = getUniqueValues(dataset, name_field)
        category_list = getUniqueValues(dataset, category_field)

        seriesData = []
        for ul in uniqueList:
        print(ul)
        dict = {}
        dict['name'] = ul;

        dict['data'] = [nameTodata[data_field] for nameTodata in dataset if nameTodata[name_field] == ul]
        seriesData.append(dict)
    '''

    ## ******  ( Category for multiple value of each Legend) ******* (End)


    category_list = getUniqueValues(dataset, category_field)
    seriesData = []
    dict = {}

    dict['data'] = [nameTodata['cnt'] for nameTodata in dataset]
    seriesData.append(dict)

    jsonForChart = json.dumps({'cat_list': category_list, 'total': seriesData}, default=decimal_date_default)

    return jsonForChart



"""
For Dashboard --- End
"""


'''
utility function for running raw queries -- Start
'''


def __db_fetch_values(query):
    cursor = connection.cursor()
    cursor.execute(query)
    fetchVal = cursor.fetchall()
    cursor.close()
    return fetchVal


def __db_fetch_single_value(query):
    cursor = connection.cursor()
    cursor.execute(query)
    fetchVal = cursor.fetchone()
    cursor.close()
    return fetchVal[0]


def __db_fetch_values_dict(query):
    cursor = connection.cursor()
    cursor.execute(query)
    fetchVal = dictfetchall(cursor)
    cursor.close()
    return fetchVal


def dictfetchall(cursor):
    desc = cursor.description
    return [
        OrderedDict(zip([col[0] for col in desc], row))
        for row in cursor.fetchall()]


def run_query(query):
    cursor = connection.cursor()
    cursor.execute(query)
    connection.commit()
    cursor.close()



def __unicode__(self):
    return unicode(self.id)

def makeTableList(tableListQuery):
    cursor = connection.cursor()
    cursor.execute(tableListQuery)
    tableList = list(cursor.fetchall())
    return tableList


def getUniqueValues(dataset, colname):
    list = [];
    for dis in dataset:
        if dis[colname] in list:
            continue;
        else:
            list.append(dis[colname]);
    return list;




##-------------------Json Serialize (Start)--------------

def date_handler(obj):
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def decimal_default(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    raise TypeError

def decimal_date_default(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    elif hasattr(obj, 'isoformat'):
        return obj.isoformat()
    else:
        return obj

    raise TypeError



##--------------Json Serialize (end )-----------------



'''
utility function for running raw queries -- Start
'''
