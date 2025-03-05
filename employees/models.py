from django.db import models
 
# Create your models here.
 
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
 
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # Hash the password
        user.save(using=self._db)
        return user
 
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)
 
class User(AbstractBaseUser, PermissionsMixin):
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    mobile = models.CharField(max_length=15)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    is_superuser = models.BooleanField(default=False)
    
 
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name"]
 
    objects = UserManager()
 
    def __str__(self):
        return self.email
 
class Employee(models.Model):
    user = models.OneToOneField(User, related_name="employee", on_delete=models.CASCADE, null=True)
    address = models.TextField()
    designation = models.CharField(max_length=100 , default= 'SRE')
    department = models.CharField(max_length=100 , default= 'Devops')
 
    def __str__(self):
        return f"{self.user.full_name}" if self.user else "No User Assigned"