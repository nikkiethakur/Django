from django.shortcuts import render,HttpResponse
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.response import Response
from .models import User, Employee
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer, DepartmentSerializer, DesignationSerializer
import boto3
from django.conf import settings

# from storages.backends.s3boto3 import S3Boto3Storage
# Create your views here.
region_name = getattr(settings, "AWS_REGION", "us-east-1")


class DetailsViews(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        data = User.objects.all()
        details_serializer = UserSerializer(data , many = True)
        return Response(details_serializer.data)
    
class designationViews(APIView):
    def post(self, request):
        all_data = Employee.objects.all()
        input_designation =  request.data.get('designation')
        designation = Employee.objects.filter(designation = input_designation)
        if input_designation is not None:
            designation_detail_serializer = DesignationSerializer(designation , many=True) 
            return Response(designation_detail_serializer.data)
        designation_detail_serializer = DesignationSerializer(all_data , many=True)
        return Response(designation_detail_serializer.data)
    
class departmentViews(APIView):
    def post(self, request):
        all_data = Employee.objects.all()
        input_department = request.data.get('department')
        devops_department = Employee.objects.filter(department = input_department)
        if input_department is not None:
            department_detail_serializer = DepartmentSerializer(devops_department , many=True) 
            return Response(department_detail_serializer.data)
        department_detail_serializer = DepartmentSerializer(all_data , many=True)
        return Response(department_detail_serializer.data)
    
class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(email= email , password = password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            user_serializer = UserSerializer(user)
            user = authenticate(email= email , password = password)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': user_serializer.data
            })
        else:
            return Response({'detail': 'Invalid credentials'}, status=401)
        
class S3BucketView(APIView):
   s3_client = boto3.client(
       's3',                     
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_S3_REGION_NAME
    )
   def get(self,request):

            s3_bucket = self.s3_client.list_buckets()
            s3_bucket_names = [bucket_name['Name'] for bucket_name in s3_bucket.get('Buckets' , [])] 

            Content = {}
            for s3_bucket_name in s3_bucket_names:
                s3_content = self.s3_client.list_objects_v2(Bucket = s3_bucket_name)

                Content[s3_bucket_name] = [contents['Key'] for contents in s3_content.get('Contents' , [])]

            return Response({
                "Bucket_name":s3_bucket_name,
                "Content": Content
            })


class EC2InstanceView(APIView):
    def get(self, request):
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_EC2_REGION_NAME
        )

        # Get all available AWS regions
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        ec2_instances = {}

        for region in regions:
            ec2 = boto3.client(
                'ec2',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=region
            )

            # Get running instances in this region
            response = ec2.describe_instances()

            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append({
                        "InstanceId": instance["InstanceId"],
                        "State": instance["State"]["Name"],
                        "Type": instance["InstanceType"],
                        "PublicIP": instance.get("PublicIpAddress", "N/A"),
                        "PrivateIP": instance.get("PrivateIpAddress", "N/A"),
                        "LaunchTime": str(instance["LaunchTime"])
                    })

            # Only add non-empty regions
            if instances:
                ec2_instances[region] = instances

        return Response({"EC2_Instances": ec2_instances})