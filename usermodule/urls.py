from django.conf.urls import patterns, include, url
from django.contrib import admin
from onadata.apps.usermodule import views,views_project

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^register/$', views.register, name='register'),
    url(r'^error/$', views.error_page, name='error_page'),
    url(r'^add-organization/$', views.add_organization, name='add_organization'),
    url(r'^organizations/$', views.organization_index, name='organization_index'),
    url(r'^edit-organization/(?P<org_id>\d+)/$', views.edit_organization, name='edit_organization'),
    # url(r'^organization-mapping/$', views.organization_mapping, name='organization_mapping'),
    url(r'^organization-delete/(?P<org_id>\d+)/$', views.delete_organization, name='organization_delete'),
    # url(r'^organization-delete-mapping/(?P<org_id>\d+)/$', views.delete_organization_mapping, name='delete_organization_mapping'),
    url(r'^edit/(?P<user_id>\d+)/$', views.edit_profile, name='edit_profile'),
    url(r'^delete/(?P<user_id>\d+)/$', views.delete_user, name='delete_user'),
    url(r'^reset-password/(?P<reset_user_id>\d+)/$', views.reset_password, name='reset_password'),
    url(r'^login/$', views.user_login, name='login'),
    url(r'^logout/$', views.user_logout, name='logout'),
    url(r'^change-password/$', views.change_password, name='change_password'),
    url(r'^locked-users/$', views.locked_users, name='locked_users'),
    url(r'^unlock/$', views.unlock, name='unlock'),
    url(r'^organization-access-list/$', views.organization_access_list, name='organization_access_list'),
    # menu item urls 
    url(r'^add-menu/$', views.add_menu, name='add_menu'),
    url(r'^menu-list/$', views.menu_index, name='menu_index'),
    url(r'^edit-menu/(?P<menu_id>\d+)/$', views.edit_menu, name='edit_menu'),
    url(r'^delete-menu/(?P<menu_id>\d+)/$', views.delete_menu, name='delete_menu'),

    # role items urls
    url(r'^add-role/$', views.add_role, name='add_role'),
    url(r'^roles-list/$', views.roles_index, name='roles_index'),
    url(r'^edit-role/(?P<role_id>\d+)/$', views.edit_role, name='edit_role'),
    url(r'^delete-role/(?P<role_id>\d+)/$', views.delete_role, name='delete_role'),
    
    # role menu map urls
    url(r'^add-role-menu-map/$', views.add_role_menu_map, name='add_role_menu_map'),
    url(r'^role-menu-map-list/$', views.role_menu_map_index, name='role_menu_map_index'),
    url(r'^edit-role-menu-map/(?P<item_id>\d+)/$', views.edit_role_menu_map, name='edit_role_menu_map'),
    url(r'^delete-role-menu-map/(?P<item_id>\d+)/$', views.delete_role_menu_map, name='delete_role_menu_map'),

    url(r"^(?P<username>\w+)/get/sent_datalist/$", views.sent_datalist, name='sent_datalist'),
    
    # user role map urls
    url(r'^organization-roles/$', views.organization_roles, name='organization_roles'),
    url(r'^user-role-map/(?P<org_id>\d+)/$', views.user_role_map, name='user_role_map'),
    url(r'^adjust-user-role-map/(?P<org_id>\d+)/$', views.adjust_user_role_map, name='adjust_user_role_map'),

    url(r'^user-viewable-projects/$', views_project.user_viewable_projects, name='user_viewable_projects'),
    url(r'^adjust-user-project-map/(?P<id_string>[^/]+)/(?P<form_owner_user>[^/]+)$', views_project.adjust_user_project_map, name='adjust_user_project_map'),
    
    # new project view url
    url(r'^(?P<username>\w+)/projects-views/(?P<id_string>[^/]+)/$', views_project.custom_project_window, name='custom_project_window'),
    url(r'^(?P<username>\w+)/projects-views/(?P<id_string>[^/]+)/generate_report/$', views_project.generate_pivot, name='generate_pivot'),

    # url(r"^(?P<username>\w+)/forms/(?P<id_string>[^/]+)/view-data",
    #     'onadata.apps.viewer.views.data_view'),

    #chart related ajax query url
    url(r'^chartview/$', views_project.chart_view, name='chart_view'),


    # For DashBoard *******
    url(r'^getTrainingData/$', views.getTrainingData, name='getTrainingData'),
    url(r'^getJsonDataForTraining/$', views.getJsonDataForTraining, name='getJsonDataForTraining'),

url(r'^mobile_register/$', views.mobile_register, name='mobile_register'),
url(r'^mobile_user_approval/$', views.mobile_user_approval, name='mobile_user_approval'),
url(r'^approve_user/$', views.approve_user, name='approve_user'),
url(r'^reject_user/$', views.reject_user, name='reject_user'),
url(r'^getInstitution/$', views.getInstitution, name='getInstitution'),

    )
