from django.contrib import admin
from django.urls import path, include
from employees import views

urlpatterns = [
    # path('employees/' , views.vsl ,name = 'home')
    path('register/', views.RegisterView.as_view()),
    path('login/', views.LoginView.as_view()),
    path('get_details/', views.DetailsViews.as_view()),
    path('get_designation/', views.designationViews.as_view()),
    path('get_department/', views.departmentViews.as_view()),
    path('get_s3/', views.S3BucketView.as_view()),
    path('get_ec2/', views.EC2InstanceView.as_view()),
    
]
