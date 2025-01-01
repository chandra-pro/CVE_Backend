"""
====================
views.py
API logic implementation for CVEHMI
Author: Chandramani Kumar, Shubham
===================
 
"""



from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from .forms import UserLoginForm
from django.db import connection
from multiprocessing import Process,Queue
from rest_framework_simplejwt.authentication import JWTAuthentication                                        
from django.utils import timezone
from datetime import datetime
import subprocess
import csv
from django.db import transaction
import pandas as pd
import datetime
import shutil
import psutil
import json
import os
import logging
from django.http import FileResponse, Http404
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import FileResponse, Http404
from django.contrib.auth import authenticate
from .models import Profile,XML,Project,Permission,ScanResult,RunningScanHistory,MyUser,ShareHistory,ProjectModification,Project,ProjectFilter
from .serializers import UserSerializer,ProjectSerializer,XMLSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.db.models import Case, When, F, Subquery, OuterRef, CharField, Value
from django.db.models.functions import Coalesce
from django.http import JsonResponse
from django.conf import settings
from datetime import datetime
import sys
sys.path.append((os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))))
from serverapp.models import CVESyncLog

LOGS_DIR = os.path.join(settings.BASE_DIR, 'hmiapp', 'media', 'logs')


def setup_logging(username):
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_file_path = os.path.join(LOGS_DIR, f"{username}_scan.log")

    # Create a new logger with a unique name for this user session
    logger = logging.getLogger(f'user_logger_{username}')
    logger.setLevel(logging.INFO)

    # Remove any existing handlers to avoid duplicate logging
    if logger.handlers:
        logger.handlers.clear()

    
    if os.path.exists(log_file_path):
        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()
            if lines and "User logged in successfully." in lines[-1]:
                
                file_handler = logging.FileHandler(log_file_path, mode='w')
            else:
                
                file_handler = logging.FileHandler(log_file_path, mode='a')
    else:
        
        file_handler = logging.FileHandler(log_file_path, mode='w')

    file_handler.setLevel(logging.INFO)

    # Create a formatter and add it to the handler
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(file_handler)

    return logger


def setup_scan_logging(scan_id):
    """Setup logging for scan with a specific log file for the scan."""
    log_file_path = os.path.join(LOGS_DIR, f"{scan_id}_scan.log")
    
    # Create a new logger instance with a unique name
    scan_logger = logging.getLogger(f'scan_logger_{scan_id}')
    scan_logger.setLevel(logging.INFO)
    
    # Clear any existing handlers
    scan_logger.handlers = []
    
    # Create file handler
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Add handler to logger
    scan_logger.addHandler(file_handler)
    
    return scan_logger

# Load paths from config.json
CONFIG_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..','..', 'config.json'))

def load_paths_from_config():    
    if not os.path.exists(CONFIG_FILE_PATH):
        print(f"Config file {CONFIG_FILE_PATH} not found.")
        return None

    with open(CONFIG_FILE_PATH, 'r') as config_file:
        config_data = json.load(config_file)
        return config_data

def check_path_exists(path, path_name):
    if os.path.exists(path):
        print(f"{path_name} exists: {path}")
        

    else:
        print(f"{path_name} does NOT exist: {path}. Creating directory...")
        print(f"{path_name} does NOT exist: {path}. Creating directory...")
        os.makedirs(path)
        print(f"Directory created: {path}")
        



#######################################################################################################
# Logic for login a user

class LoginView(APIView):
    """
    Handles login for both local DB and LDAP users.
    """
    def post(self, request, *args, **kwargs):
        form = UserLoginForm(request.data)
        if form.is_valid():
            try:
                user = form.cleaned_data.get('user_obj')
                if user:
                    username = user.username
                    logger = setup_logging(username)
                    refresh = RefreshToken.for_user(user)
                    tokens = {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    }
                    logger.info("User logged in successfully.")

                    # Fetch or create profile
                    profile, created = Profile.objects.get_or_create(user=user)
                    if created or not profile.first_name:
                        profile.first_name = form.cleaned_data.get('first_name', '')
                        profile.last_name = form.cleaned_data.get('last_name', '')
                        profile.title = form.cleaned_data.get('title', '')
                        profile.photo = form.cleaned_data.get('photo', '')
                        profile.save()

                    user_data = UserSerializer(user).data
                    user_data['profile'] = {
                        'first_name': profile.first_name,
                        'last_name': profile.last_name,
                        'title': profile.title,
                        'photo': profile.photo,
                    }

                    return Response({
                        'tokens': tokens,
                        'user': user_data
                    }, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f"Server error during login: {str(e)}")
                return Response(
                    {'detail': 'An error occurred while processing your request. Please try again later.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        logger.warning("Invalid credentials provided.")
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)



#######################################################################################################
# Logout logic implementation of user


class LogoutView(APIView):
    """
    Handles user logout by blacklisting the refresh token.
    """
    def post(self, request):
        try:
            username = request.user.username
            logger = setup_logging (username)
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)



#######################################################################################################
# Logic implemented for token refreshment

@permission_classes([AllowAny]) 
class TokenRefreshView(APIView):
    """
    Refreshes an access token using a refresh token.
    """
    def post(self, request):
        try:
            username = request.user.username
            logger = setup_logging(username)
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
            token = RefreshToken(refresh_token)
            access_token = str(token.access_token)
            expiration = token.access_token.payload.get('exp')  # Get the expiration time from the token payload
            return Response({"access": access_token, "expires_at": expiration}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)



#######################################################################################################
# Logic implemented to authorize user 


class UserView(APIView):
    """
    Verifies the user's token and returns user data.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user  # The authenticated user

        # Serialize the user data
        user_data = UserSerializer(user).data  # Assuming UserSerializer includes necessary user fields
        user_data['is_active'] = user.is_active
        user_data['is_admin'] = user.is_staff

        # Fetch profile information if available
        try:
            profile = Profile.objects.get(user=user)  # Assuming there is a one-to-one relationship
            user_data['first_name'] = profile.first_name
            user_data['last_name'] = profile.last_name
            user_data['title'] = profile.title
            user_data['photo'] = profile.photo.url if profile.photo else None  # Handle optional photo field
        except Profile.DoesNotExist:
            # Profile not found, handle if necessary (e.g., return defaults or log)
            user_data['first_name'] = None
            user_data['last_name'] = None
            user_data['title'] = None
            user_data['photo'] = None

        return Response(user_data, status=status.HTTP_200_OK)



#######################################################################################################
# Logic implemented to add a project


class AddProjectView(APIView):
    """
    API View to handle adding a new project with improved error handling.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        username = request.user.username
        logger = setup_logging(username)

        logger.info(f"Request Headers: {request.headers}")
        logger.info(f"Authenticated User: {request.user}")

        data = request.data
        user = request.user  

        created_paths = []

        try:
            # Load paths from config.json
            try:
                config_data = load_paths_from_config()
                if not config_data:
                    return Response({'detail': 'Configuration not found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                upload_path = config_data.get('upload_dir', None)
                download_path = config_data.get('download_dir', None)

                if not upload_path or not download_path:
                    return Response({'detail': 'Upload or download path is not defined in config.json.'}, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                logger.error(f"Error loading configuration: {str(e)}")
                return Response({'detail': 'Error loading configuration.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            try:
                check_path_exists(upload_path, "Upload Path")
                check_path_exists(download_path, "Download Path")
            except Exception as e:
                logger.error(f"Error checking paths: {str(e)}")
                return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            if 'user' not in data:
                data['user'] = user.id

            existing_project = Project.objects.filter(user=user, project_name=data.get('project_name')).first()
            if existing_project:
                return Response({'detail': 'A project with this name already exists.'},
                                status=status.HTTP_400_BAD_REQUEST)

            serializer = ProjectSerializer(data=data)
            if not serializer.is_valid():
                logger.error(f"Serializer errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            project = serializer.save()
            created_project = project

            project_upload_path = os.path.join(upload_path, user.username, project.project_name)
            try:
                os.makedirs(project_upload_path, exist_ok=True)
                created_paths.append(project_upload_path)
            except Exception as e:
                logger.error(f"Error creating project directory: {str(e)}")
                raise Exception('Error creating project directory.')

            manifest_path = os.path.join(project_upload_path, 'manifest')
            try:
                os.makedirs(manifest_path, exist_ok=True)
                created_paths.append(manifest_path)
            except Exception as e:
                logger.error(f"Error creating manifest directory: {str(e)}")
                raise Exception('Error creating manifest directory.')

            # Prepare XML data
            xml = XML(user=user, project=project)
            xml.tool_use = data.get('tool_select')
            xml.project_version = data.get('project_version')

            # Validate and process the manifest file
            manifest_file_path = None
            if 'prj_xml_path' in request.FILES:
                manifest_file = request.FILES['prj_xml_path']
                manifest_file_name = manifest_file.name
                file_extension = get_file_extension(manifest_file_name)

                # Check if the file extension is valid
                if file_extension not in ['.txt', '.csv', '.xlsx', '.manifest']:
                    raise Exception('Invalid file extension for manifest file. Only .txt, .csv, .xlsx, or .manifest allowed.')

                # Read and validate the content of the manifest file
                try:
                    manifest_file_path = os.path.join(manifest_path, manifest_file_name)
                    with open(manifest_file_path, 'wb+') as dest:
                        for chunk in manifest_file.chunks():
                            dest.write(chunk)

                    with open(manifest_file_path, 'r') as file:
                        reader = csv.reader(file, delimiter=' ')
                        for row in reader:
                            if len(row) != 3:
                                os.remove(manifest_file_path)
                                raise Exception('Invalid manifest file content. Each row must have exactly 3 columns.')

                    xml.xml_path = manifest_file_path
                except Exception as e:
                    if manifest_file_path and os.path.exists(manifest_file_path):
                        os.remove(manifest_file_path)
                    raise

            # Handle uploading of blacklisting file
            blacklisting_file_path = os.path.join(project_upload_path, 'blacklist')
            try:
                os.makedirs(blacklisting_file_path, exist_ok=True)
                created_paths.append(blacklisting_file_path)
            except Exception as e:
                logger.error(f"Error creating blacklist directory: {str(e)}")
                raise Exception('Error creating blacklist directory.')

            # Handle blacklist file if uploaded
            if 'blacklist_file' in request.FILES:
                blacklist_file = request.FILES['blacklist_file']
                blacklist_file_name = blacklist_file.name
                file_extension = get_file_extension(blacklist_file_name)

                # Check if the file extension is valid
                if file_extension not in ['.csv', '.xlsx']:
                    raise Exception('Invalid file extension for blacklist file. Only .csv or .xlsx allowed.')

                # Save the blacklist file
                blacklist_file_path = os.path.join(blacklisting_file_path, blacklist_file.name)
                os.makedirs(os.path.dirname(blacklist_file_path), exist_ok=True)

                with open(blacklist_file_path, 'wb+') as dest:
                    for chunk in blacklist_file.chunks():
                        dest.write(chunk)

                # Validate the contents of the blacklist file
                try:
                    if file_extension == '.csv':
                        with open(blacklist_file_path, 'r') as file:
                            reader = csv.reader(file)
                            for row in reader:
                                if len(row) != 1:  # Ensure only one column
                                    os.remove(blacklist_file_path)
                                    raise Exception('The CVE IDs to be blacklisted should be in the first column of the file.')

                    elif file_extension == '.xlsx':
                        df = pd.read_excel(blacklist_file_path)
                        if df.shape[1] != 1:  # Ensure only one column
                            os.remove(blacklist_file_path)
                            raise Exception('The CVE IDs to be blacklisted should be in the first column of the file.')

                    xml.blacklist_path = blacklist_file_path  # Save the path to the XML instance

                except Exception as e:
                    if os.path.exists(blacklist_file_path):
                        os.remove(blacklist_file_path)
                    raise

            try:
                if 'build_file_paths' in request.FILES:
                    build_file = request.FILES['build_file_paths']
                    build_file_path = os.path.join(download_path, user.username, project.project_name, build_file.name)
                    os.makedirs(os.path.dirname(build_file_path), exist_ok=True)
                    with open(build_file_path, 'wb+') as dest:
                        for chunk in build_file.chunks():
                            dest.write(chunk)
                    xml.build_file = build_file_path  # Save the path to the XML instance
            except Exception as e:
                logger.error(f"Error saving additional files: {str(e)}")
                raise Exception('Error saving additional files.')

            # Add GitHub and branch details
            try:
                if 'github_link' in data:
                    xml.github_link = data['github_link']
                if 'github_branch' in data:
                    xml.branch = data['github_branch']
                if 'stable_branch' in data:  # Assuming this is now `dot_kernel_branch`
                    xml.dot_kernel_branch = data['stable_branch']  # Map to the correct field
                if 'kernel_version' in data:
                    xml.kernel_version = data['kernel_version']
                xml.save()  # Save the XML instance
            except Exception as e:
                logger.error(f"Error saving XML data: {str(e)}")
                raise Exception('Error saving XML data.')

            # Create permission entry
            try:
                permission = Permission(user=user, project=project, write='Admin')
                permission.save()
            except Exception as e:
                logger.error(f"Error creating permission: {str(e)}")
                raise Exception('Error creating permission entry.')

            # Return success response
            project_data = ProjectSerializer(project).data
            return Response({
                'detail': 'Project created successfully.',
                'project': project_data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Rollback: Delete created project and remove created paths
            logger.error(f"Error in project creation: {str(e)}")

            # Delete XML instance if created
            try:
                if 'xml' in locals():
                    xml.delete()
            except:
                pass

            # Delete project from database
            try:
                if 'created_project' in locals():
                    created_project.delete()
            except:
                pass

            # Remove created directories
            for path in created_paths:
                try:
                    import shutil
                    shutil.rmtree(path, ignore_errors=True)
                except:
                    pass

            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    

def get_filename(path, file_extension):
    """
       This method removes the unique appended key from the filename.
       | **path**: XML File Path
       | **file_extension**: extension(.csv/.txt) of XML File 
    """
    path = str(path).split('/')[1]
    path = os.path.splitext(path)[0].split('_')[0] + file_extension
    return path

def get_file_extension(filename):
    """
        This method returns the file extension(.csv/.txt)
        | **filename**: XML File Path
    """
    file_extension = os.path.splitext(filename)[1]
    return file_extension



#######################################################################################################
# Logic implemented to modify project


class ModifyProjectView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, project_id):
        username = request.user.username
        logger = setup_logging(username)
        logger.debug(f"User: {request.user}, Project ID: {project_id}")
        try:
            # Fetch the project based on project_id
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            logger.warning(f"Project not found: {project_id}")
            return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Check if the user has appropriate permissions to modify the project
            permission = Permission.objects.get(project=project, user=request.user)
            if permission.write not in ['Write', 'Admin']:
                return Response({'detail': 'You do not have permission to modify this project.'}, status=status.HTTP_403_FORBIDDEN)
        except Permission.DoesNotExist:
            return Response({'detail': 'You do not have permission to access this project.'}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        user = request.user
        modification_detail = []  # Collect all modifications in a single list

        # Load paths from config.json
        config_data = load_paths_from_config()
        if not config_data:
            return Response({'detail': 'Configuration not found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        upload_path = config_data.get('upload_dir', None)
        download_path = config_data.get('download_dir', None)

        if not upload_path or not download_path:
            return Response({'detail': 'Upload or download path is not defined in config.json.'}, status=status.HTTP_400_BAD_REQUEST)

        # Update project details
        original_project_name = project.project_name
        project.project_name = data.get('project_name', project.project_name)
        if original_project_name != project.project_name:
            modification_detail.append(f"Project name changed from {original_project_name} to {project.project_name}")
        project.save()

        # Update or create XML object
        xml_obj, created = XML.objects.get_or_create(project=project, user=user)

        xml_obj.tool_use = data.get('tool_select', xml_obj.tool_use)

        if not xml_obj.tool_use:
            logger.warning("Tool Select is missing in the request data.")
        xml_obj.project_version = data.get('project_version', xml_obj.project_version)
        xml_obj.github_link = data.get('github_link', xml_obj.github_link)
        xml_obj.branch = data.get('github_branch', xml_obj.branch)
        xml_obj.dot_kernel_branch = data.get('stable_branch', xml_obj.dot_kernel_branch)
        xml_obj.kernel_version = data.get('kernel_version', xml_obj.kernel_version)

        # Handle file updates
        project_upload_path = os.path.join(upload_path, user.username, project.project_name)
        manifest_path = os.path.join(project_upload_path, 'manifest')
        os.makedirs(manifest_path, exist_ok=True)
        
        # Initialize added and deleted rows
        added_rows = []
        deleted_rows = []

        
        # Validate and process the manifest file
        manifest_file_path = None
        if 'prj_xml_path' in request.FILES:
            manifest_file = request.FILES['prj_xml_path']
            manifest_file_name = manifest_file.name
            file_extension = get_file_extension(manifest_file_name)
            old_xml_path = str(xml_obj.xml_path) if xml_obj.xml_path else None
            if old_xml_path:
                xml_obj.kernel_version = None

            # Check if the file extension is valid
            if file_extension not in ['.txt', '.csv', '.xlsx', '.manifest']:
                return Response({'detail': 'Invalid file extension for manifest file. Only .txt, .csv, .xlsx, or .manifest allowed.'}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # Read and validate the content of the manifest file
            try:
                manifest_file_path = os.path.join(manifest_path, manifest_file_name)
                with open(manifest_file_path, 'wb+') as dest:
                    for chunk in manifest_file.chunks():
                        dest.write(chunk)

                with open(manifest_file_path, 'r') as file:
                    reader = csv.reader(file, delimiter=' ')
                    for row in reader:
                        if len(row) != 3:
                            os.remove(manifest_file_path)
                            return Response({'detail': 'Invalid manifest file content. Each row must have exactly 3 columns.'}, 
                                            status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                logger.error(f"Error processing manifest file: {str(e)}")
                if manifest_file_path and os.path.exists(manifest_file_path):
                    os.remove(manifest_file_path)
                return Response({'detail': 'Error processing the manifest file.'}, status=status.HTTP_400_BAD_REQUEST)

            # Compare old and new manifest files to detect differences
            old_xml_path = str(xml_obj.xml_path) if xml_obj.xml_path else None
            if old_xml_path and os.path.exists(old_xml_path):
                added_rows, deleted_rows = self.compare_manifest_files(request, old_xml_path, manifest_file_path)
                modification_detail.append(f"Manifest file updated: {len(added_rows)} rows added, {len(deleted_rows)} rows deleted.")
            
            else:
                with open(manifest_file_path, 'r') as new_file:
                    new_lines = new_file.readlines()

                logger.debug(f"New Manifest Contents:\n{''.join(new_lines)}")
                new_packages = {line.strip() for line in new_lines}
                added_rows = list(new_packages)

            if old_xml_path != manifest_file_path:
                modification_detail.append(f"Project XML file path changed from {old_xml_path} to {manifest_file_path}")


            xml_obj.xml_path = manifest_file_path

        # Handle build file upload and track changes
        if 'build_file_paths' in request.FILES:
            build_file = request.FILES['build_file_paths']
            build_file_path = os.path.join(download_path, user.username, project.project_name, build_file.name)
            os.makedirs(os.path.dirname(build_file_path), exist_ok=True)
            with open(build_file_path, 'wb+') as dest:
                for chunk in build_file.chunks():
                    dest.write(chunk)
            if xml_obj.build_file != build_file_path:
                modification_detail.append(f"Build file path changed from {xml_obj.build_file} to {build_file_path}")
                xml_obj.build_file = build_file_path

        # Blacklisting file modification handling
        blacklist_file_path = None
        if 'blacklist_file' in request.FILES:
            blacklist_file = request.FILES['blacklist_file']
            blacklist_file_name = blacklist_file.name
            file_extension = get_file_extension(blacklist_file_name)

            # Validate the blacklisting file extension
            if file_extension not in ['.xlsx', '.csv']:
                return Response({'detail': 'Invalid file extension for blacklisting file. Only .xlsx or .csv allowed.'}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # Read and validate the content of the blacklisting file
            try:
                blacklist_file_path = os.path.join(project_upload_path, 'blacklist', blacklist_file_name)
                os.makedirs(os.path.dirname(blacklist_file_path), exist_ok=True)

                # Save file to the blacklisting path
                with open(blacklist_file_path, 'wb+') as dest:
                    for chunk in blacklist_file.chunks():
                        dest.write(chunk)

                # Validate that the file has only 1 column
                if file_extension == '.csv':
                    with open(blacklist_file_path, 'r') as file:
                        reader = csv.reader(file)
                        for row in reader:
                            if len(row) != 1:
                                os.remove(blacklist_file_path)
                                return Response({'detail': 'Invalid blacklisting file content. File must have exactly 1 column.'}, 
                                                status=status.HTTP_400_BAD_REQUEST)
                elif file_extension == '.xlsx':
                    import pandas as pd
                    df = pd.read_excel(blacklist_file_path)
                    if df.shape[1] != 1:
                        os.remove(blacklist_file_path)
                        return Response({'detail': 'Invalid blacklisting file content. File must have exactly 1 column.'}, 
                                        status=status.HTTP_400_BAD_REQUEST)

                modification_detail.append("Blacklisting file uploaded successfully.")
            except Exception as e:
                logger.error(f"Error processing blacklisting file: {str(e)}")
                if blacklist_file_path and os.path.exists(blacklist_file_path):
                    os.remove(blacklist_file_path)
                return Response({'detail': 'Error processing the blacklisting file.'}, status=status.HTTP_400_BAD_REQUEST)

        # Save the XML object and log the modification details
        xml_obj.blacklist_path = blacklist_file_path
        xml_obj.save()

        # Log the modification if any changes were made
        if modification_detail:
            ProjectModification.objects.create(
                project=project,
                user=user,
                modification_detail="; ".join(modification_detail),
                added_rows=json.dumps(added_rows) if added_rows else json.dumps([]),  
                deleted_rows=json.dumps(deleted_rows) if deleted_rows else json.dumps([])  
            )

        # Return success response
        return Response({
            'detail': 'Project updated successfully.',
            'project': ProjectSerializer(project).data
        }, status=status.HTTP_200_OK)

    def compare_manifest_files(self, request, old_manifest_path, new_manifest_path):
        """
        Compare old and new manifest files and return the added and deleted rows.
        """
        username = request.user.username
        logger = setup_logging(username)
        with open(old_manifest_path, 'r') as old_file:
            old_lines = old_file.readlines()

        with open(new_manifest_path, 'r') as new_file:
            new_lines = new_file.readlines()

        logger.info(f"Old Manifest Contents:\n{''.join(old_lines)}")
        logger.info(f"New Manifest Contents:\n{''.join(new_lines)}")

        old_packages = {line.strip() for line in old_lines}
        new_packages = {line.strip() for line in new_lines}

        added_rows = list(new_packages - old_packages)
        deleted_rows = list(old_packages - new_packages)

        logger.info(f"Added Rows: {added_rows}")
        logger.info(f"Deleted Rows: {deleted_rows}")

        return added_rows, deleted_rows



#######################################################################################################
# Logic implemented to delete project

class ProjectDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete_file_if_exists(self, file_field):

        if file_field and file_field.name:
            file_path = os.path.join(settings.MEDIA_ROOT, file_field.name)
            print(f"Attempting to delete file: {file_path}")
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
                except OSError as e:
                    print(f"Error deleting file {file_path}: {str(e)}")

    def delete_scan_results(self, project):
        
        scan_results = ScanResult.objects.filter(project=project)
        print(f"Deleting {scan_results.count()} scan results for project ID {project.id}")

        for scan_result in scan_results:
            # Delete the report directory for this scan
            if scan_result.scan_report_path:
                report_dir = os.path.dirname(scan_result.scan_report_path)
                print(f"Attempting to delete report directory: {report_dir}")
                if os.path.exists(report_dir):
                    try:
                        shutil.rmtree(report_dir)
                        print(f"Deleted report directory: {report_dir}")
                    except OSError as e:
                        print(f"Error deleting report directory {report_dir}: {str(e)}")

            # Delete any downloaded results
            if scan_result.download_result:
                self.delete_file_if_exists(scan_result.download_result)

    def delete_xml_files(self, project):
        
        xmls = XML.objects.filter(project=project)
        print(f"Deleting {xmls.count()} XML files for project ID {project.id}")

        for xml in xmls:
            # Delete associated files
            self.delete_file_if_exists(xml.xml_path)
            self.delete_file_if_exists(xml.source_path)
            self.delete_file_if_exists(xml.blacklist_path)
            self.delete_file_if_exists(xml.build_file)

    def delete(self, request, project_id):
        username = request.user.username
        print(f"User {username} initiated deletion for project ID {project_id}")

        try:
            project = Project.objects.get(id=project_id)
            print(f"Project {project_id} found")
        except Project.DoesNotExist:
            print("Project not found")
            return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user has admin permissions
        try:
            permission = Permission.objects.get(project=project, user=request.user)
            if permission.write != 'Admin':
                print("User does not have admin permission")
                return Response(
                    {'detail': 'You do not have permission to delete this project.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            print("User has admin permission")
        except Permission.DoesNotExist:
            print("Permission not found for user")
            return Response(
                {'detail': 'You do not have permission to access this project.'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            # Delete all scan results and their files
            print("Deleting scan results...")
            self.delete_scan_results(project)

            # Delete all XML files
            print("Deleting XML files...")
            self.delete_xml_files(project)

            # Delete related data
            print("Deleting running scan history, project modifications, filters, share history, notifications, and permissions...")
            RunningScanHistory.objects.filter(projectid=str(project_id)).delete()
            ProjectModification.objects.filter(project=project).delete()
            ProjectFilter.objects.filter(project=project).delete()
            ShareHistory.objects.filter(project=project).delete()

            Permission.objects.filter(project=project).delete()

            # Finally delete the project
            project.delete()
            print(f"Project {project_id} and all associated data successfully deleted.")

            return Response(
                {"detail": "Project and all associated data successfully deleted."},
                status=status.HTTP_204_NO_CONTENT
            )
        except Exception as e:
            print(f"Error during project deletion: {str(e)}")
            return Response(
                {'detail': f'Error deleting project: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#######################################################################################################
# Logic implemented to list out all the projects for each user



class UserProjectsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        username = request.user.username
        logger = setup_logging(username)

        user = request.user  # Get the authenticated user

        # Fetch the projects owned by the user
        own_projects = Project.objects.filter(user=user)

        # Fetch the projects shared with the user from ShareHistory
        shared_projects = Project.objects.filter(sharehistory__shared_user=user)

        # Combine both querysets
        all_projects = own_projects | shared_projects

        # Annotate the real owner field for shared projects
        all_projects = all_projects.annotate(
            real_owner=Coalesce(
                Case(
                    When(user=user, then=F('user__username')),  # When the user is the owner
                    default=Subquery(
                        ShareHistory.objects.filter(project=OuterRef('pk')).values('user__username')[:1]
                    ),  # Otherwise, get the owner from ShareHistory
                    output_field=CharField()
                ),
                Value('Unknown Owner'),  # Fallback if Subquery returns None
                output_field=CharField()
            )
        )

        # Serialize the projects
        serializer = ProjectSerializer(all_projects.distinct(), many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

#######################################################################################################
# Logic implemented to list out all the valid projects to share



class ShareProjectsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user  # Get the authenticated user

        # Fetch the projects owned by the user
        own_projects = Project.objects.filter(user=user)

        # Fetch the projects shared with the user where permission is 'Admin'
        shared_projects_with_admin_permission = Project.objects.filter(
            permission__user=user,  
            permission__write='Admin'  
        )

    
        # Combine both querysets
        all_projects = own_projects | shared_projects_with_admin_permission

        # Annotate the real owner field for shared projects
        all_projects = all_projects.annotate(
            real_owner=Coalesce(
                Case(
                    When(user=user, then=F('user__username')),
                    default=Subquery(
                        ShareHistory.objects.filter(project=OuterRef('pk')).values('user__username')[:1]
                    ), 
                    output_field=CharField()
                ),
                Value('Unknown Owner'), 
                output_field=CharField()
            )
        )

        # Serialize the projects
        serializer = ProjectSerializer(all_projects.distinct(), many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


#######################################################################################################
# Logic implemented to list out details of each project



class ProjectDetailView(APIView):
    """
    API View to retrieve details of a specific project for the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id, *args, **kwargs):
        user = request.user  # Get the authenticated user

        try:
            # Fetch the project based on project_id and ensure it belongs to the authenticated user
            project = Project.objects.get(id=project_id)

            # Check if the user is the owner or has permissions to access the project
            if not (project.user == user or Permission.objects.filter(project=project, user=user).exists()):
                return Response({'detail': 'You do not have permission to view this project.'}, status=status.HTTP_403_FORBIDDEN)
        except Project.DoesNotExist:
            return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the project data
        project_serializer = ProjectSerializer(project)

        # Fetch and serialize associated XML records
        xml_records = XML.objects.filter(project=project)
        xml_serializer = XMLSerializer(xml_records, many=True)

        # Combine project and XML data in the response
        response_data = {
            'project': project_serializer.data,
            'xml_records': xml_serializer.data
        }

        return Response(response_data, status=status.HTTP_200_OK)
    
#######################################################################################################
# Logic to view all the Scans running in the background


class ActiveScansSSEView(APIView):
    def get(self, request):
        # Get only running background scans
        running_background_scans = RunningScanHistory.objects.filter(running_background=True)

        # Prepare list to store active scans with project name included
        active_scans = []

        for scan in running_background_scans:
            # Get the project name from the Project model using the projectid
            project = Project.objects.filter(id=scan.projectid).first()

            # If project is found, include project_name, else default to None
            project_name = project.project_name if project else None

            # Prepare the scan data
            scan_data = {
                'user': scan.user.username,
                'projectid': scan.projectid,
                'pid': scan.pid,
                'created_at': scan.created_at,
                'running_background': scan.running_background,
                'excel_report_path': scan.excel_report_path,
                'html_report_path': scan.html_report_path,
                'project_name': project_name  # Add project_name to the response
            }

            active_scans.append(scan_data)

        # Return the list of active scans as JSON
        return JsonResponse(active_scans, safe=False)   


#######################################################################################################
# Logic to make the field running_background to true


class StartBackgroundScanView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        pro_id = request.data.get('project_id')

        # Set running_background to True for this project ID
        RunningScanHistory.objects.update_or_create(
            projectid=pro_id,
            defaults={'running_background': True}
        )

        return JsonResponse({'status': 'success', 'message': 'Background scan started successfully.'}) 
    
    

#######################################################################################################
# Logic implemented to scan specific project



class ScanXMLProjectView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, project_id):
        
        try:
            user = request.user
            username = request.user.username
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_id = timestamp
            setup_scan_logging(scan_id)
            logger = setup_logging(username)
            log_file_path = os.path.join(LOGS_DIR, f"{username}_scan.log")
            logger.info("Starting scan for project ID: %s", project_id)
            project = Project.objects.get(id=project_id)
            original_user= user
            scan_date = timezone.now().date()
            
            try:
                # Check if the user is the original owner
                xml_obj = XML.objects.filter(project=project, user=user).first()

                if not xml_obj:
                    # User is not the owner, check ShareHistory
                    share_history = ShareHistory.objects.filter(project=project, shared_user=user).order_by('-timestamp').first()
                    if not share_history:
                        return Response({'detail': 'No record found in ShareHistory for this project and user.'}, status=status.HTTP_404_NOT_FOUND)

                    # Fetch the original sharer (who shared the project)
                    original_sharer = share_history.user
                    original_user = share_history.user

                    # Fetch the XML object related to the project, created by the original sharer
                    xml_obj = XML.objects.filter(project=project, user=original_sharer).first()

                    if not xml_obj:
                        return Response({'detail': 'XML file not found for the project shared by the original user.'}, status=status.HTTP_404_NOT_FOUND)
            
            except ShareHistory.DoesNotExist:
                return Response({'detail': 'You do not have permission to access this project.'}, status=status.HTTP_403_FORBIDDEN)

            # Load paths from config.json
            try:
                config_data = load_paths_from_config()
                if not config_data:
                    return Response({'detail': 'Configuration not found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                upload_path = config_data.get('upload_dir', None)
                download_path = config_data.get('download_dir', None)

                if not upload_path or not download_path:
                    return Response({'detail': 'Upload or download path is not defined in config.json.'}, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                logger.error(f"Error loading configuration: {str(e)}")
                return Response({'detail': 'Error loading configuration.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Check and create the main upload and download paths if they do not exist
            try:
                check_path_exists(upload_path, "Upload Path")
                check_path_exists(download_path, "Download Path")
            except Exception as e:
                logger.error(f"Error checking paths: {str(e)}")
                return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            manifest_base_path = upload_path
            project_base_path = '/cve-checker-tool-4.0'

            # Extract necessary fields from XML object
            xml_path = None
            kernel_version = None
            blacklist_path = None

            if xml_obj.xml_path:
                relative_path = xml_obj.xml_path.name
                xml_path = os.path.join(manifest_base_path, relative_path)
                if not os.path.exists(xml_path):
                    return Response({'detail': f'Manifest file not found at {xml_path}'}, status=status.HTTP_404_NOT_FOUND)
            if xml_obj.kernel_version:
                kernel_version = xml_obj.kernel_version

            if xml_obj.blacklist_path:
                relative_blacklist_path = xml_obj.blacklist_path.name
                blacklist_path = os.path.join(manifest_base_path, relative_blacklist_path)
                if blacklist_path and not os.path.exists(blacklist_path):
                    return Response({'detail': f'Blacklist file not found at {blacklist_path}'}, status=status.HTTP_404_NOT_FOUND)        

            project_name = project.project_name
            project_version = xml_obj.project_version
            github_link = xml_obj.github_link
            github_branch = xml_obj.branch
            stable_branch = xml_obj.dot_kernel_branch
            buildfile = xml_obj.build_file

            
            username = user.username
            logger.info("Starting scan for project ID: %s", project_id)

            # Define paths for logs and reports
            report_dir = os.path.join(project_base_path, 'hmi', 'CVEHMI', 'hmiapp', 'media', 'reports')
            log_dir = os.path.join(project_base_path, 'hmi', 'CVEHMI','hmiapp', 'media', 'logs')
            script_path = os.path.join(project_base_path, 'cli', 'Client')

            # Ensure directories exist
            for directory in [report_dir, log_dir, script_path]:
                if not os.path.exists(directory):
                    return Response({'detail': f'Directory not found: {directory}'}, status=status.HTTP_404_NOT_FOUND)
            
            scan_report_path = os.path.join(report_dir, username, str(project_id), str(scan_id))
            log_path = os.path.join(log_dir, f'{request.user.username}_scan.log')

            # Check which tool to use and run the appropriate method
            procs = []
            return_queue = Queue()
                    
                    
            if xml_obj.tool_use == "CVEHMI":
                if not xml_path:
                    return Response({'detail': 'XML path is required for CVEHMI tool.'}, status=status.HTTP_400_BAD_REQUEST)
                
                scan_successful = Process(target=runCVETool, args=(request, scan_report_path, script_path, xml_path, project_name, project_version, project_id, log_dir,scan_id, blacklist_path, return_queue))

            elif xml_obj.tool_use == "PKCT":
                # Check for required fields
                if not github_link:
                    return Response({'detail': 'GitHub link is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)
                if not github_branch:
                    return Response({'detail': 'GitHub branch is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)
                if not stable_branch:
                    return Response({'detail': 'Stable branch is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)
                if not buildfile:
                    return Response({'detail': 'Build file is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)

                # Check for xml_path or kernel_version
                if not xml_path and not kernel_version:
                    return Response({'detail': 'Either XML path or kernel version is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)
                
            
                build_path = None
                
                if xml_obj.build_file:
                    relative_path = xml_obj.build_file.name
                    build_path = os.path.join(manifest_base_path, relative_path)
                    if not os.path.exists(build_path):
                        return Response({'detail': f'Manifest file not found at {xml_path}'}, status=status.HTTP_404_NOT_FOUND)
                      
                scan_successful = Process(target=runPKCTTool, args=(request,scan_report_path, script_path, xml_path, kernel_version, project_name, project_version, project_id, log_dir,
                    github_link, github_branch, stable_branch, build_path,original_user,scan_id, blacklist_path, return_queue))

            elif xml_obj.tool_use == "Integrated": 
                # Check for required fields
                if not github_link:
                    return Response({'detail': 'GitHub link is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)
                if not github_branch:
                    return Response({'detail': 'GitHub branch is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)
                if not stable_branch:
                    return Response({'detail': 'Stable branch is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)
                if not buildfile:
                    return Response({'detail': 'Build file is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)

                # Check for xml_path or kernel_version
                if not xml_path:
                    return Response({'detail': 'XML path is required for PKCT tool.'}, status=status.HTTP_400_BAD_REQUEST)
            
                build_path = None
                
                if xml_obj.build_file:
                    relative_path = xml_obj.build_file.name
                    build_path = os.path.join(manifest_base_path, relative_path)
                    if not os.path.exists(build_path):
                        return Response({'detail': f'Manifest file not found at {xml_path}'}, status=status.HTTP_404_NOT_FOUND)
                      
                scan_successful = Process(target=runIntegrated, args=(request,scan_report_path, script_path, xml_path, project_name, project_version, project_id, log_dir,
                    github_link, github_branch, stable_branch, build_path,original_user,scan_id, blacklist_path, return_queue))                   
            else:
                return Response({'detail': 'Invalid tool selected.'}, status=status.HTTP_400_BAD_REQUEST)
            procs.append(scan_successful)
            scan_successful.start()
            for scan in procs:
                    scan.join()
            logger.info("Exit Code of Process.")
            

            exit_code,error_message = return_queue.get()
            logger.info(exit_code)

            scan_result = ScanResult(
                xml=xml_obj,
                project=project,
                user=user,
                scan_id=scan_id,
                scan_report_path=scan_report_path,
                date_scanned=scan_date,
                project_logs=log_path,
                tool_use=xml_obj.tool_use,
                exit_code=exit_code  # Save the exit code
            )
            scan_result.save()

            
            logger.info("Scan completed and results saved successfully.")

            # Check if the scan was aborted (exit code -15)
            if exit_code == -15:
                return Response({'detail': 'Scan aborted Successfully.'}, status=status.HTTP_200_OK)
            
            elif exit_code == 0:
            # if scan_successful:           

                logger.info("Scan completed and results saved successfully.")                

                return Response({
                    'detail': 'Scan completed successfully.',
                    'scan_id': scan_id,
                    'project_Id': project_id
                }, status=status.HTTP_201_CREATED)

            else:
                logger.error("Scan failed.")
                return Response({'detail': f'Scan unsuccessful! Please check the logs. Error: {error_message.strip()}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Project.DoesNotExist:
            return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return Response({'detail': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    




def runCVETool(request, scan_report_path, script_path, xml_path, project_name, project_version, project_id, log_dir,scan_id, blacklist_path, return_queue):
    os.chdir(script_path)
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

    username = request.user.username
    logger = setup_logging(username)
    scan_logger = setup_scan_logging(scan_id)

    

    command = [
        'python3', os.path.join(script_path, 'cvechecker_report.py'),
        '-m', xml_path,
        '--username', request.user.username,
        '--project_id', str(project_id),
        '--scan_id', str(scan_id),
    ]

    # Add blacklist path if it exists
    if blacklist_path:
        command.extend(['--blacklist', blacklist_path])

    # Fetch the latest filter for the project (filter with the greatest id for the project_id)
    filters = ProjectFilter.objects.filter(project_id=project_id).order_by('-id').first()    

    # Check if new filters are provided in the request
    new_filters = request.data.get('filters', None)  # Expecting filters in the request body

    if new_filters:
        # If new filters are provided, create or update the project filters
        if filters:
            filters.description = new_filters.get('description', filters.description)
            filters.cvss_v2 = new_filters.get('cvss_v2', filters.cvss_v2)
            filters.cvss_v3_1 = new_filters.get('cvss_v3_1', filters.cvss_v3_1)
            filters.weaknesses = new_filters.get('weaknesses', filters.weaknesses)
            filters.references = new_filters.get('references', filters.references)
            filters.published_date = new_filters.get('published_date', filters.published_date)
            filters.cvss_v2_base = new_filters.get('cvss_v2_base', filters.cvss_v2_base)
            filters.cvss_v2_exploitability = new_filters.get('cvss_v2_exploitability', filters.cvss_v2_exploitability)
            filters.cvss_v2_impact = new_filters.get('cvss_v2_impact', filters.cvss_v2_impact)
            filters.cvss_v3_1_base = new_filters.get('cvss_v3_1_base', filters.cvss_v3_1_base)
            filters.cvss_v3_1_exploitability = new_filters.get('cvss_v3_1_exploitability', filters.cvss_v3_1_exploitability)
            filters.cvss_v3_1_impact = new_filters.get('cvss_v3_1_impact', filters.cvss_v3_1_impact)
            filters.report_name = new_filters.get('report_name', filters.report_name)
            filters.save()  # Save the updated filters
        else:
            # If no existing filters, create a new ProjectFilter instance
            filters = ProjectFilter.objects.create(project_id=project_id, **new_filters)  

    # Append sections based on what's selected
    sections = []
    if filters:
        if filters.description:
            sections.append('Description')
        if filters.cvss_v2:
            sections.append('CVSSV2')
        if filters.cvss_v3_1:
            sections.append('CVSSV3.1')
        if filters.weaknesses:
            sections.append('Weaknesses')
        if filters.references:
            sections.append('References')

        if sections:
            command.append('--sections')
            command.extend(sections)  # Append sections as individual arguments

        # Collect filter arguments
        filter_arguments = []     

        if filters.published_date:
            filter_arguments.append('PublishedDate')
            filter_arguments.append(filters.published_date)

        if filters.cvss_v2_base:
            filter_arguments.append('CVSSV2Base')
            filter_arguments.append(filters.cvss_v2_base)

        if filters.cvss_v2_exploitability:
            filter_arguments.append('CVSSV2Exploitability')
            filter_arguments.append(filters.cvss_v2_exploitability)

        if filters.cvss_v2_impact:
            filter_arguments.append('CVSSV2Impact')
            filter_arguments.append(filters.cvss_v2_impact)

        if filters.cvss_v3_1_base:
            filter_arguments.append('CVSSV3.1Base')
            filter_arguments.append(filters.cvss_v3_1_base)

        if filters.cvss_v3_1_exploitability:
            filter_arguments.append('CVSSV3.1Exploitability')
            filter_arguments.append(filters.cvss_v3_1_exploitability)

        if filters.cvss_v3_1_impact:
            filter_arguments.append('CVSSV3.1Impact')
            filter_arguments.append(filters.cvss_v3_1_impact)

        # Add all filter arguments to the command
        if filter_arguments:
            command.append('--filter')
            command.extend(filter_arguments)  # Add each filter and value as separate items           

        report_name = []

        if filters.report_name:
            report_name.append(filters.report_name)       

        if report_name:
            command.append('--report_name')
            command.extend(report_name)
    
    logger.info(f"Executing command: {' '.join(command)}")
    scan_logger.info(f"Executing command: {' '.join(command)}")

    with transaction.atomic():
        running_scan = RunningScanHistory.objects.create(
            user=request.user,
            projectid=project_id,
            pid=None 
        )

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process_id = process.pid

        with transaction.atomic():
            running_scan.pid = process_id
            running_scan.save()

        logger.info(f"Running scan saved with PID: {process_id}")
        scan_logger.info(f"Running scan saved with PID: {process_id}")

        stdout, stderr = process.communicate()

        rc = process.returncode

        if rc == 0:
            # Normal exit with success
            logger.info("CVETool ran successfully.")
            scan_logger.info("CVETool ran successfully.")
            running_scan.delete()  # Remove the scan from history since it completed
            return_queue.put((0,"Successful scan"))
            
        
        elif rc == -15:
            logger.info("process return id is -15")
            scan_logger.info("process return id is -15")
            # Scan was aborted
            logger.warning("CVETool was aborted.")
            scan_logger.warning("CVETool was aborted.")
            running_scan.delete()  # Remove aborted scan from history
            return_queue.put((-15, "Abort scan successfully"))# Indicate scan was not successful due to abort
            

        else:
            # Other errors
            logger.error(f"CVETool failed with exit code: {process.returncode}, stderr: {stderr.decode()}")
            scan_logger.error(f"CVETool failed with exit code: {process.returncode}, stderr: {stderr.decode()}")
            running_scan.delete()  # Remove from history as it failed
            error_message = f"cve_search_manifest.py failed with exit code {rc}.\n\nError output:\n{stderr.strip()}"
            return_queue.put((rc,error_message))

    except Exception as e:
        logger.error(f"An error occurred while running CVETool: {e}")
        scan_logger.error(f"An error occurred while running CVETool: {e}")
        running_scan.delete()  # Remove if an error occurs
        return_queue.put((-1,str(e)))
        


          


def runPKCTTool(request, scan_report_path, script_path, xml_path, kernel_version, project_name, project_version, project_id, log_dir,
                github_link, github_branch, stable_branch, build_path,original_user,scan_id, blacklist_path, return_queue):
    """
    This method scans all packages and generates the report using the PKCT tool.
    """
    os.chdir(script_path)
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

    username = request.user.username
    logger = setup_logging(username)
    scan_logger = setup_scan_logging(scan_id)
    
    
    command = [
        'python3', os.path.join(script_path, 'pkct_report.py'),
        '-gk', github_link,
        '-gb', github_branch,
        '-db', stable_branch,
        '--username', username,
        '--project_id', str(project_id),
        '--scan_id', str(scan_id)
        
        ]
    

    if blacklist_path:
        command.extend(['--blacklist', blacklist_path])
    if build_path:
        command.extend(['-build', build_path])
    if xml_path and kernel_version:
        command.extend(['-v', kernel_version])
    elif kernel_version:
        command.extend(['-v', kernel_version])
    elif xml_path:
        command.extend(['-m', xml_path])    
    if original_user:
        command.extend(['-u', str(original_user.username)])
    if project_name:
        command.extend(['-pname',project_name])


    # Fetch the latest filter for the project (filter with the greatest id for the project_id)
    filters = ProjectFilter.objects.filter(project_id=project_id).order_by('-id').first()    

    # Check if new filters are provided in the request
    new_filters = request.data.get('filters', None)  # Expecting filters in the request body

    if new_filters:
        # If new filters are provided, create or update the project filters
        if filters:
            
            filters.description = new_filters.get('description', filters.description)
            filters.cvss_v2 = new_filters.get('cvss_v2', filters.cvss_v2)
            filters.cvss_v3_1 = new_filters.get('cvss_v3_1', filters.cvss_v3_1)
            filters.weaknesses = new_filters.get('weaknesses', filters.weaknesses)
            filters.references = new_filters.get('references', filters.references)
            filters.patch_status = new_filters.get('patch_status', filters.patch_status)            
            filters.published_date = new_filters.get('published_date', filters.published_date)
            filters.cvss_v2_base = new_filters.get('cvss_v2_base', filters.cvss_v2_base)
            filters.cvss_v2_exploitability = new_filters.get('cvss_v2_exploitability', filters.cvss_v2_exploitability)
            filters.cvss_v2_impact = new_filters.get('cvss_v2_impact', filters.cvss_v2_impact)
            filters.cvss_v3_1_base = new_filters.get('cvss_v3_1_base', filters.cvss_v3_1_base)
            filters.cvss_v3_1_exploitability = new_filters.get('cvss_v3_1_exploitability', filters.cvss_v3_1_exploitability)
            filters.cvss_v3_1_impact = new_filters.get('cvss_v3_1_impact', filters.cvss_v3_1_impact)
            filters.report_name = new_filters.get('report_name', filters.report_name)
            filters.save()  # Save the updated filters
        else:
            # If no existing filters, create a new ProjectFilter instance
            filters = ProjectFilter.objects.create(project_id=project_id, **new_filters)  

    # Append sections based on what's selected
    sections = []
    if filters:
        if filters.description:
            sections.append('Description')
        if filters.cvss_v2:
            sections.append('CVSSV2')
        if filters.cvss_v3_1:
            sections.append('CVSSV3.1')
        if filters.weaknesses:
            sections.append('Weaknesses')
        if filters.references:
            sections.append('References')

        if sections:
            command.append('--sections')
            command.extend(sections)  # Append sections as individual arguments

        # Collect filter arguments
        filter_arguments = []     

        if filters.patch_status:
            filter_arguments.append('PatchStatus')
            filter_arguments.extend(filters.patch_status.split())

        if filters.published_date:
            filter_arguments.append('PublishedDate')
            filter_arguments.append(filters.published_date)

        if filters.cvss_v2_base:
            filter_arguments.append('CVSSV2Base')
            filter_arguments.append(filters.cvss_v2_base)

        if filters.cvss_v2_exploitability:
            filter_arguments.append('CVSSV2Exploitability')
            filter_arguments.append(filters.cvss_v2_exploitability)

        if filters.cvss_v2_impact:
            filter_arguments.append('CVSSV2Impact')
            filter_arguments.append(filters.cvss_v2_impact)

        if filters.cvss_v3_1_base:
            filter_arguments.append('CVSSV3.1Base')
            filter_arguments.append(filters.cvss_v3_1_base)

        if filters.cvss_v3_1_exploitability:
            filter_arguments.append('CVSSV3.1Exploitability')
            filter_arguments.append(filters.cvss_v3_1_exploitability)

        if filters.cvss_v3_1_impact:
            filter_arguments.append('CVSSV3.1Impact')
            filter_arguments.append(filters.cvss_v3_1_impact)

        # Add all filter arguments to the command
        if filter_arguments:
            command.append('--filter')
            command.extend(filter_arguments)  # Add each filter and value as separate items     

        report_name = []

        if filters.report_name:
            report_name.append(filters.report_name)       

        if report_name:
            command.append('--report_name')
            command.extend(report_name)


            

    logger.info(f"Executing PKCT command: {' '.join(command)}")
    scan_logger.info(f"Executing PKCT command: {' '.join(command)}")
    with transaction.atomic():
        running_scan = RunningScanHistory.objects.create(
            user=request.user,
            projectid=project_id,
            pid=None 
        )

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process_id = process.pid

        with transaction.atomic():
            running_scan.pid = process_id
            running_scan.save()

        logger.info(f"Running scan saved with PID: {process_id}")
        scan_logger.info(f"Running scan saved with PID: {process_id}")

        stdout, stderr = process.communicate()
        rc = process.returncode

        if rc == 0:
            # Normal exit with success
            logger.info("PKCT Tool ran successfully.")
            scan_logger.info("PKCT Tool ran successfully.")
            running_scan.delete()  # Remove the scan from history since it completed
            return_queue.put((0,"Successful Scan"))
            

                    
        elif rc == -15:
            print("process return id is -15")
            # Scan was aborted
            logger.warning("PKCT Tool was aborted.")
            scan_logger.warning("PKCT Tool was aborted.")
            running_scan.delete()  # Remove aborted scan from history
            return_queue.put((-15,"Scan aborted successfully"))
            

        else:
            # Other errors
            logger.error(f"PKCT Tool failed with exit code: {process.returncode}, stderr: {stderr.decode()}")
            scan_logger.error(f"PKCT Tool failed with exit code: {process.returncode}, stderr: {stderr.decode()}")
            running_scan.delete()  # Remove from history as it failed
            error_message = f"pkct_main.py failed with exit code {rc}.\n\nError output:\n{stderr.strip()}"
            return_queue.put((rc, error_message))
            

    except Exception as e:
        logger.error(f"An error occurred while running CVETool: {e}")
        scan_logger.error(f"An error occurred while running CVETool: {e}")
        running_scan.delete()  # Remove if an error occurs
        return_queue.put((-1,str(e)))
        


           


def runIntegrated(request, scan_report_path, script_path, xml_path, project_name, project_version, project_id, log_dir,
                github_link, github_branch, stable_branch, build_path,original_user,scan_id, blacklist_path, return_queue):
    """
    This method scans all packages and generates the report using the PKCT tool.
    """
    os.chdir(script_path)
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
    username = request.user.username
    logger = setup_logging(username)    
    scan_logger = setup_scan_logging(scan_id)

    
    command = [
        'python3', os.path.join(script_path, 'integrated.py'),
        '-gk', github_link,
        '-gb', github_branch,
        '-db', stable_branch,
        '--username', username,
        '--project_id', str(project_id),
        '--scan_id', str(scan_id)
    ]
    master_branch="master"
    if blacklist_path:
        command.extend(['--blacklist', blacklist_path])
    if build_path:
        command.extend(['-build', build_path])
    if xml_path:
        command.extend(['-m', xml_path])
    if original_user:
        command.extend(['-u', str(original_user.username)])
    if project_name:
        command.extend(['-pname',project_name])
    command.extend(['-ub',master_branch])

    # Fetch the latest filter for the project (filter with the greatest id for the project_id)
    filters = ProjectFilter.objects.filter(project_id=project_id).order_by('-id').first()    

    # Check if new filters are provided in the request
    new_filters = request.data.get('filters', None)  # Expecting filters in the request body

    if new_filters:
        # If new filters are provided, create or update the project filters
        if filters:
            
            filters.description = new_filters.get('description', filters.description)
            filters.cvss_v2 = new_filters.get('cvss_v2', filters.cvss_v2)
            filters.cvss_v3_1 = new_filters.get('cvss_v3_1', filters.cvss_v3_1)
            filters.weaknesses = new_filters.get('weaknesses', filters.weaknesses)
            filters.references = new_filters.get('references', filters.references)
            filters.patch_status = new_filters.get('patch_status', filters.patch_status)
            filters.published_date = new_filters.get('published_date', filters.published_date)
            filters.cvss_v2_base = new_filters.get('cvss_v2_base', filters.cvss_v2_base)
            filters.cvss_v2_exploitability = new_filters.get('cvss_v2_exploitability', filters.cvss_v2_exploitability)
            filters.cvss_v2_impact = new_filters.get('cvss_v2_impact', filters.cvss_v2_impact)
            filters.cvss_v3_1_base = new_filters.get('cvss_v3_1_base', filters.cvss_v3_1_base)
            filters.cvss_v3_1_exploitability = new_filters.get('cvss_v3_1_exploitability', filters.cvss_v3_1_exploitability)
            filters.cvss_v3_1_impact = new_filters.get('cvss_v3_1_impact', filters.cvss_v3_1_impact)
            filters.report_name = new_filters.get('report_name', filters.report_name)
            filters.save()  # Save the updated filters
        else:
            # If no existing filters, create a new ProjectFilter instance
            filters = ProjectFilter.objects.create(project_id=project_id, **new_filters)  

    # Append sections based on what's selected
    sections = []
    if filters:
        if filters.description:
            sections.append('Description')
        if filters.cvss_v2:
            sections.append('CVSSV2')
        if filters.cvss_v3_1:
            sections.append('CVSSV3.1')
        if filters.weaknesses:
            sections.append('Weaknesses')
        if filters.references:
            sections.append('References')

        if sections:
            command.append('--sections')
            command.extend(sections)  # Append sections as individual arguments

        # Collect filter arguments
        filter_arguments = []     

        
        if filters.published_date:
            filter_arguments.append('PublishedDate')
            filter_arguments.append(filters.published_date)

        if filters.cvss_v2_base:
            filter_arguments.append('CVSSV2Base')
            filter_arguments.append(filters.cvss_v2_base)

        if filters.cvss_v2_exploitability:
            filter_arguments.append('CVSSV2Exploitability')
            filter_arguments.append(filters.cvss_v2_exploitability)

        if filters.cvss_v2_impact:
            filter_arguments.append('CVSSV2Impact')
            filter_arguments.append(filters.cvss_v2_impact)

        if filters.cvss_v3_1_base:
            filter_arguments.append('CVSSV3.1Base')
            filter_arguments.append(filters.cvss_v3_1_base)

        if filters.cvss_v3_1_exploitability:
            filter_arguments.append('CVSSV3.1Exploitability')
            filter_arguments.append(filters.cvss_v3_1_exploitability)

        if filters.cvss_v3_1_impact:
            filter_arguments.append('CVSSV3.1Impact')
            filter_arguments.append(filters.cvss_v3_1_impact)

        if filters.patch_status:
            filter_arguments.append('PatchStatus')
            filter_arguments.extend(filters.patch_status.split())

        # Add all filter arguments to the command
        if filter_arguments:
            command.append('--filter')
            command.extend(filter_arguments)  # Add each filter and value as separate items     

        report_name = []

        if filters.report_name:
            report_name.append(filters.report_name)       

        if report_name:
            command.append('--report_name')
            command.extend(report_name)



    logger.info(f"Executing Integrated command: {' '.join(command)}")
    scan_logger.info(f"Executing Integrated command: {' '.join(command)}")
    with transaction.atomic():
        running_scan = RunningScanHistory.objects.create(
            user=request.user,
            projectid=project_id,
            pid=None 
        )

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process_id = process.pid

        with transaction.atomic():
            running_scan.pid = process_id
            running_scan.save()

        logger.info(f"Running scan saved with PID: {process_id}")
        scan_logger.info(f"Running scan saved with PID: {process_id}")

        stdout, stderr = process.communicate()
        rc = process.returncode

        if rc == 0:
            # Normal exit with success
            logger.info("Integrated Tool ran successfully.")
            scan_logger.info("Integrated Tool ran successfully.")
            running_scan.delete()  # Remove the scan from history since it completed
            return_queue.put((0,"Scan successful"))
            
        
        elif rc == -15:
            print("process return id is -15")
            # Scan was aborted
            logger.warning("IntegratedTool was aborted.")
            scan_logger.warning("IntegratedTool was aborted.")
            running_scan.delete()  # Remove aborted scan from history
            return_queue.put((-15,"Scan aborted successfully"))
            

        else:
            # Other errors
            logger.error(f"Integrated Tool failed with exit code: {process.returncode}, stderr: {stderr.decode()}")
            scan_logger.error(f"Integrated Tool failed with exit code: {process.returncode}, stderr: {stderr.decode()}")
            running_scan.delete()  # Remove from history as it failed
            error_message = f"integrated.py failed with exit code {rc}.\n\nError output:\n{stderr.strip()}"
            return_queue.put((rc, error_message))
            

    except Exception as e:
        logger.error(f"An error occurred while running CVETool: {e}")
        scan_logger.error(f"An error occurred while running CVETool: {e}")
        running_scan.delete()  # Remove if an error occurs
        return_queue.put((-1,str(e)))
        



#######################################################################################################
# Logic implemented to list out scan history

class ScanHistoryView(APIView):
    """
    API View to retrieve the scan history for a specific project,
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id, *args, **kwargs):
        username = request.user.username
        logger = setup_logging(username)
        setup_logging(username)

        # Retrieve only the successful scan results for the specified project ID
        try:
            
            project_scans = ScanResult.objects.filter(
                project_id=project_id,
                exit_code=0  # Filter for successful scans only
            ).order_by("-scan_timestamp")

            arr = []
            for i in project_scans:
                data = {}
                scan_report_path = i.scan_report_path
                report_info = scan_report_path.split('/')  # Split the path

                # Ensure there are enough segments in the report_info
                if len(report_info) < 2:
                    logger.warning("ScanHistoryView: Not enough segments in report_info for scan ID %s", i.scan_id)
                    continue  # Skip this iteration

                date_time = i.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S').split(' ')
                if len(date_time) < 2:
                    logger.warning("ScanHistoryView: Not enough segments in date_time for scan ID %s", i.scan_id)
                    continue  # Skip this iteration

                formatted_timestamp = i.scan_timestamp.strftime('%d/%m/%y %H:%M:%S')
                data['date'] = formatted_timestamp
                data['report_name'] = os.path.splitext(report_info[-1])[0]
                data['report_file_path'] = scan_report_path  
                data['scan_id'] = i.scan_id
                data['user'] = i.user.username  # Assuming `user` is a ForeignKey to User model
                data['tool_use'] = i.tool_use
                arr.append(data)

            logger.info("ScanHistoryView: Retrieved scan history successfully for project ID %s", project_id)
            return Response({'report_history': arr}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error("ScanHistoryView: Error retrieving scan history: %s", str(e))
            return Response({'detail': 'Error retrieving scan history.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def get_path(arr):
        return os.path.join(*arr)

    
#######################################################################################################
# All Scan Results

class AllScanHistoryView(APIView):
    """
    API View to retrieve the complete scan history for a specific project, including all scans (successful and failed).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id, *args, **kwargs):
        username = request.user.username
        logger = setup_logging(username)

        

        try:
            # Retrieve all scan results for the specified project ID
            all_scans = ScanResult.objects.filter(project_id=project_id).order_by("-scan_timestamp")
            
            scan_history = []
            for scan in all_scans:
                scan_data = {}
                scan_report_path = scan.scan_report_path
                report_info = scan_report_path.split('/') if scan_report_path else []

                # Ensure there are enough segments in the report_info
                if len(report_info) < 2:
                    logger.warning(f"AllScanHistoryView: Not enough segments in report_info for scan ID {scan.scan_id}")
                    continue  # Skip this iteration

                formatted_timestamp = scan.scan_timestamp.strftime('%d/%m/%y %H:%M:%S')
                scan_data['date'] = formatted_timestamp
                scan_data['report_name'] = os.path.splitext(report_info[-1])[0] if report_info else 'N/A'
                scan_data['report_file_path'] = scan_report_path
                scan_data['scan_id'] = scan.scan_id
                scan_data['user'] = scan.user.username if scan.user else 'N/A'
                scan_data['tool_use'] = scan.tool_use
                scan_data['exit_code'] = scan.exit_code
                scan_data['status'] = 'Success' if scan.exit_code == 0 else 'Failed'
                scan_data['log_name'] = f"{scan.scan_id}_log"
                
                scan_history.append(scan_data)

            logger.info(f"AllScanHistoryView: Retrieved all scan history successfully for project ID {project_id}")
            return Response({'all_scan_history': scan_history}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"AllScanHistoryView: Error retrieving all scan history: {str(e)}")
            return Response({'detail': 'Error retrieving all scan history.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def get_path(arr):
        return os.path.join(*arr)

    



#######################################################################################################
# Logic implemented to abort scan


class AbortScanView(APIView):
    """
    API View to abort a running scan for the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        username = request.user.username
        logger = setup_logging(username)
        project_id = request.data.get('project_id', None)

        running_scan_entry = RunningScanHistory.objects.filter(user=request.user, projectid=project_id).first()

        if running_scan_entry is None:
            return JsonResponse({'status': 'error', 'message': 'No running scan found for this project.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            logger.info(f"Aborting scan with PID: {running_scan_entry.pid}")
            subprocess.run(['kill', str(running_scan_entry.pid)], check=True)

            running_scan_entry.delete()

            response_data = {'status': 'success', 'message': 'Scan aborted successfully'}
            return JsonResponse(response_data, status=status.HTTP_200_OK)

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to kill process {running_scan_entry.pid}: {e}")
            return JsonResponse({'status': 'error', 'message': 'Failed to abort scan.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return JsonResponse({'status': 'error', 'message': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




#######################################################################################################
# Logic implemented to share project


class ShareProjectView(APIView):
    def post(self, request, *args, **kwargs):
        username = request.user.username
        logger = setup_logging(username)
        data = request.data
        project_id = data.get('project_id')
        receiver_username_or_email = data.get('receiver_username_or_email')
        permission_type = data.get('permission_type')

        # Validate required fields
        if not all([project_id, receiver_username_or_email, permission_type]):
            return Response({'error': 'Missing required fields: project_id, receiver_username_or_email, permission_type'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        # Check if the project exists and belongs to the authenticated user
        try:
            project = Project.objects.get(id=project_id, user=request.user)
        except Project.DoesNotExist:
            logger.warning(f"Project with id {project_id} not found for user {request.user.username}.")
            return Response({'error': 'Project not found or you do not have permission to access it.'}, 
                            status=status.HTTP_404_NOT_FOUND)

        # Check if the user has permission to share the project (Admin only)
        try:
            permission = Permission.objects.get(project=project, user=request.user)
            if permission.write != 'Admin':
                logger.warning(f"User {request.user.username} tried to share project {project_id} without Admin permissions.")
                return Response({'detail': 'You do not have permission to share this project.'}, 
                                status=status.HTTP_403_FORBIDDEN)
        except Permission.DoesNotExist:
            logger.warning(f"No permissions found for user {request.user.username} on project {project_id}.")
            return Response({'detail': 'You do not have permission to access this project.'}, 
                            status=status.HTTP_403_FORBIDDEN)

        # Perform LDAP lookup to get receiver's email
        try:
            receiver_email = os.popen(
                'ldapsearch -x -h ldap.inn.mentorg.com -b "DC=mgc,DC=mentorg,DC=com" "name={}" | grep mail | cut -d " " -f2'.format(receiver_username_or_email)
            ).read().strip()

            if not receiver_email:
                logger.warning(f"User {receiver_username_or_email} not found in LDAP.")
                return Response({'error': 'User not found in LDAP'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error during LDAP search for user {receiver_username_or_email}: {e}")
            return Response({'error': 'Error during LDAP lookup. Please try again later.'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Check if the user already exists in the local database
        try:
            receiver = MyUser.objects.get(username=receiver_username_or_email)
            if not receiver.is_active:
                logger.warning(f"User {receiver_username_or_email} is not active.")
                return Response({'error': 'User is not active.'}, status=status.HTTP_403_FORBIDDEN)
        except MyUser.DoesNotExist:
            # Create a new user without setting a password (LDAP will handle authentication)
            try:
                receiver = MyUser.objects.create(
                    username=receiver_username_or_email,
                    email=receiver_email,
                    is_active=True
                )
                receiver.set_unusable_password()  # Prevent local login with a password; LDAP required
                receiver.save()
            except Exception as e:
                logger.error(f"Failed to create user {receiver_username_or_email}: {e}")
                return Response({'error': 'Error creating user. Please try again later.'}, 
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Assign permissions for the project
        try:
            with transaction.atomic():
                Permission.objects.update_or_create(
                    project=project,
                    user=receiver,
                    defaults={'write': permission_type}  # Store the permission type
                )

                # Log sharing in ShareHistory
                ShareHistory.objects.create(
                    project=project,
                    user=request.user,
                    shared_user=receiver,
                    project_name=project.project_name
                )
        except Exception as e:
            logger.error(f"Failed to assign permissions for project {project_id} to user {receiver.username}: {e}")
            return Response({'error': 'Error assigning permissions. Please try again later.'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'Project shared successfully'}, status=status.HTTP_200_OK)




#######################################################################################################
# Logic implemented to list out all the changes made for any proejct


class ProjectModificationHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id):
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

        modifications = ProjectModification.objects.filter(project=project).order_by('-modification_time')
        history_data = [
            {
                'user': mod.user.username,
                'modification_time': mod.modification_time,
                'modification_detail': mod.modification_detail,
                'added_rows': json.loads(mod.added_rows) if mod.added_rows else [],  # Parse JSON
                'deleted_rows': json.loads(mod.deleted_rows) if mod.deleted_rows else []  # Parse JSON

            }
            for mod in modifications
        ]

        return Response({'modification_history': history_data}, status=status.HTTP_200_OK)


def pdf_url_view(request):
    pdf_url = f'{request.build_absolute_uri(settings.MEDIA_URL)}public/help.pdf'
    return JsonResponse({'pdf_url': pdf_url})

#################################################################################################
#API to save filters for respective projects in User Projects List

@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Ensure the user is authenticated
def save_filters(request):
    project_id = request.data.get('projectId')
    filters = request.data.get('filters')

    try:
        project = Project.objects.get(id=project_id)
        project_filter = ProjectFilter(
            project=project,
            description=filters['sections'].get('description', False),
            cvss_v2=filters['sections'].get('cvssV2', False),
            cvss_v3_1=filters['sections'].get('cvssV3_1', False),
            weaknesses=filters['sections'].get('weaknesses', False),
            references=filters['sections'].get('references', False),
            published_date=filters['textFilters'].get('publishedDate', None),
            patch_status=filters['textFilters'].get('patchStatus', None),  # Check this line
            cvss_v2_base=filters['textFilters'].get('cvssV2Base', ''),
            cvss_v2_exploitability=filters['textFilters'].get('cvssV2Exploitability', ''),
            cvss_v2_impact=filters['textFilters'].get('cvssV2Impact', ''),
            cvss_v3_1_base=filters['textFilters'].get('cvssV3_1Base', ''),
            cvss_v3_1_exploitability=filters['textFilters'].get('cvssV3_1Exploitability', ''),
            cvss_v3_1_impact=filters['textFilters'].get('cvssV3_1Impact', ''),
            report_name=filters['textFilters'].get('reportName', '')
        )
        project_filter.save()
        return Response({'message': 'Filters saved successfully.'}, status=status.HTTP_201_CREATED)
    except Project.DoesNotExist:
        return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

################################################################################################
#API To Download Log File 

class LogDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        username = request.user.username
        return self.download_log(request, username)

    def download_log(self, request, username):
        log_file = f"{username}_scan.log"
        log_url = f'{request.build_absolute_uri(settings.MEDIA_URL)}logs/{log_file}'
        return JsonResponse({'log_url': log_url}) 

##################################################################################################
#API To Reports

class ReportDownloadView(APIView):
    """
    API View to retrieve the download URL for a specific scan report.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id, scan_id, *args, **kwargs):
        try:
            # Assuming you have a way to get the username from the request or context
            username = request.user.username  
            logger = setup_logging(username)
            projectID = str (project_id)
            
            # Build the report URL dynamically
            report_url = f"{request.build_absolute_uri(settings.MEDIA_URL)}reports/download/download_{scan_id}.html"
            
            # Optionally, log the generated URL for debugging
            logger.info("Generated report URL: %s", report_url)
            
            return JsonResponse({'report_url': report_url}, status=200)
        except Exception as e:
            logger.error("Error retrieving report URL for project ID %s and scan ID %s: %s", project_id, scan_id, str(e))
            return JsonResponse({'detail': 'Error retrieving report URL.'}, status=500)
        
##########################################################################################
# API To Download Logs for each scan

class ScanLogDownloadView(APIView):
    """
    API View to retrieve and download log file for a specific scan.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id, scan_id, *args, **kwargs):
        try:
            # Assuming you have a way to get the username from the request or context
            username = request.user.username
            logger = setup_logging(username)

            # Construct the log file URL similar to how reports are constructed
            log_url = f"{request.build_absolute_uri(settings.MEDIA_URL)}logs/{scan_id}_scan.log"

            # Optionally, log the generated URL for debugging
            logger.info("Generated Log File URL: %s", log_url)

            # Check if the file exists at the location
            log_file_path = os.path.join(settings.MEDIA_ROOT, 'logs', f"{scan_id}_scan.log")
            if not os.path.exists(log_file_path):
                raise Http404("Log file not found")

            # Return the log file as a downloadable response
            response = FileResponse(open(log_file_path, 'rb'), as_attachment=True, filename=f"{scan_id}_scan.log")
            return response

        except Exception as e:
            logger.error("Error retrieving log file for project ID %s and scan ID %s: %s", project_id, scan_id, str(e))
            return JsonResponse({'detail': 'Error retrieving log file.'}, status=500)

        
#########################################################################################################

# API To fetch the last sync of CVE database update.

class CVESyncLogView(APIView):
    """
    API View to retrieve the latest CVESyncLog entry.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            # Get the latest CVESyncLog entry from the server_db database
            latest_log = CVESyncLog.objects.using('server_db').latest('created_at')

            # Serialize the data to return it in a JSON response
            log_data = {
                'last_sync': latest_log.last_sync,
                'status': latest_log.status,
                'message': latest_log.message,
                'created_at': latest_log.created_at,
            }

            return Response(log_data, status=status.HTTP_200_OK)

        except CVESyncLog.DoesNotExist:
            return JsonResponse({'detail': 'No CVE sync logs found.'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return JsonResponse({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
###########################################################################################################