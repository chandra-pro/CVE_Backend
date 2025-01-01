from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser)
from django.core.validators import RegexValidator
from django.utils import timezone
from django.db import models

class MyUserManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        """
           Creates and saves a User with the given email and password.

           | **username**: Name of the user
           | **email**: Email ID of the user
           | **password**: Password of the user
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            username=username,
            email=self.normalize_email(email),
        )
        
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        """
           Creates and saves a superuser with the given email and password.

           | **username**: Name of the super user
           | **email**: Email ID of the super user
           | **password**: Password of the super user
        """
        user = self.create_user(
            username,
            email,
            password=password,
        )
        user.is_admin = True
        user.is_staff = True
        user.is_active = True
        user.save(using=self._db)
        return user

USERNAME_REGEX='^[a-zA-Z0-9.@+-]*$'


class MyUser(AbstractBaseUser):
    """
       This class overrides user base class.
    """
   
    username=models.CharField(max_length=120,validators=[RegexValidator(
        regex=USERNAME_REGEX,
        message="Username must be alphanumeric",
        code='invalid_username'
        )],
        unique=True,
    )
    email = models.EmailField(
        verbose_name='email address',
        max_length=255
    )
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    objects = MyUserManager()
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

class Profile(models.Model):
    """
        This class creates user profile for verification.
    """
    user = models.OneToOneField(MyUser, on_delete=models.CASCADE,related_name="profile")
    email_confirmed = models.BooleanField(default=False)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=30, blank=True, null=True)
    title = models.CharField(max_length=100, blank=True, null=True)
    photo = models.TextField(blank=True, null=True)

def post_save_user_model_receiver(sender, instance, created, *args, **kwargs):
    if created:
        try:
            new_profile = Profile.objects.get_or_create(user=instance)
        except:
            pass

post_save.connect(post_save_user_model_receiver, sender=MyUser)
# Create your models here.

import sys
import datetime

try:
        from django.db import models
        from django.contrib.auth import get_user_model
except Exception:
        print("Oops! some error occured. Make sure that you have django installed and properly configured.")
        sys.exit(0)

#Projects Table to store project related information.
#Fields : [1] User(1:M with MyUser table)[2] Project Name

class Project(models.Model):
        #Database Fields
        user = models.ManyToManyField(MyUser)
        project_name = models.CharField("Project's Name", max_length = 30, null = False)
     
        #Meta Fields    
        class Meta:
                verbose_name = 'Project'
                verbose_name_plural = 'Projects'
                db_table = 'project'

        #Utility Methods
        def __str__(self):
                return self.project_name

#Permission Table to store permission related information.
#Fields : [1] Permission(Read/Write/Admin) [2] Project(1:M with Project table)[3] User(1:M with MyUser table)[4] Timestamp of Permission

class Permission(models.Model):
    write =  models.CharField(max_length = 30, null = False)
    project = models.ForeignKey(Project,on_delete=models.CASCADE,related_name="permission")
    user = models.ForeignKey(MyUser, on_delete = models.CASCADE)
    permission_timestamp = models.DateTimeField(auto_now_add = True)

    def __str__(self):
        return self.write

#Notification Table to store notification related information.
#Fields : [1] Sender(1:M with MyUser table) [2] Receiver(1:M with MyUser table) [3] Title of the Notification [4] Project(1:M with Project table) [5] Status of Notification(seen/unseen) [6] Timestamp of Notification [7] Flag to control the close button [8] Permission requested(to store the permission)

class Notification(models.Model):
    sender = models.ForeignKey(MyUser, on_delete = models.CASCADE, related_name="sender")
    receiver = models.ForeignKey(MyUser, on_delete = models.CASCADE, related_name="receiver")
    title = models.CharField(max_length = 30, null = False)
    project = models.ForeignKey(Project,on_delete=models.CASCADE,related_name="notification")
    status = models.CharField(max_length = 30, null = False)
    notification_timestamp = models.DateTimeField(auto_now_add = True)
    show_close = models.BooleanField(default = False)
    permission_requested =  models.CharField(max_length = 30, null = True)

#XML Table to store xml related information.
#Fields : [1] Project(1:M with Project table)[2] User(1:M with MyUser table)[3] Path of XML File [4] Path of Source Code [5] Timestamp of XML File [6] Path of Diff File created between same release ID [7] Release Id of the Project [8] Path of the Diff File Created between different Release ID

class XML(models.Model):
        project = models.ForeignKey(Project,on_delete=models.CASCADE,related_name="xmls")
        user = models.ForeignKey(MyUser, on_delete = models.CASCADE)
        xml_path = models.FileField(upload_to = 'uploads/', null = True)
        source_path = models.FileField(upload_to = 'uploads/', null = True)
        blacklist_path = models.FileField(upload_to = 'uploads/', null = True)
        timestamp = models.DateTimeField(auto_now_add = True)
        diff_csv = models.CharField(max_length = 30, null = True)
        project_version = models.CharField("Project's Version", max_length = 30, null = False)
        diff_file_version = models.CharField(max_length = 30, null = True)
        kernel_version = models.CharField(max_length = 30, null = True)
        github_link = models.URLField("GitHub Link", max_length=200, null=True)
        branch = models.CharField("Branch", max_length=50, null=True)
        upstream_branch = models.CharField("Upstream Branch", max_length=50, null=True)
        dot_kernel_branch = models.CharField("Dot Kernel Branch", max_length=50, null=True)
        build_file = models.FileField("Build File", upload_to='uploads/', null=True)
        tool_use = models.CharField("Tool Selected", max_length=50,null= False)
 



from django.conf import settings
import os

class ScanResult(models.Model):
    # Database Fields
    xml = models.ForeignKey(XML, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    scan_id = models.CharField("Scan UUID", max_length=30, null=False, unique=True)
    scan_report_path = models.CharField("Report Path of the Project Scanned", max_length=255, null=False)
    date_scanned = models.DateField("Date when Project Scanned")
    scan_timestamp = models.DateTimeField(auto_now_add=True)
    project_logs = models.CharField("Logs of Project Scanned", max_length=255, null=False)
    tool_use = models.CharField("Tool Selected", max_length=50, null=False)
    download_result = models.FileField(upload_to='', blank=True, null=True)  # Ensure it's nullable and blank by default
    exit_code = models.IntegerField("Exit Code of the Scan", null=False, default = 1)  # New field for exit code

    class Meta:
        verbose_name = "Scan Result"
        verbose_name_plural = "Scan Results"
        db_table = "scanResult"

    def save(self, *args, **kwargs):
        # Automatically set the download_result path before saving
        if not self.download_result:  # If it hasn't been set yet
            report_file = f'download_{self.scan_id}.html'
            relative_path = os.path.join('reports', self.user.username, str(self.project_id), self.scan_id, report_file)
            self.download_result = os.path.join(settings.MEDIA_ROOT, relative_path)
        
        super(ScanResult, self).save(*args, **kwargs)

    def __str__(self):
        return self.scan_report_path
    
class RunningScanHistory(models.Model):
        user = models.ForeignKey(MyUser, on_delete = models.CASCADE)
        projectid = models.CharField(max_length=255)
        pid = models.PositiveIntegerField(null=True, blank=True)
        running_background = models.BooleanField(default = False)
        created_at = models.DateTimeField(auto_now_add=True)
        excel_report_path = models.CharField(max_length=255, null=True)  # Add this field
        html_report_path = models.CharField(max_length=255, null=True)    # Add this field
    
        def __str__(self):
            return f"{self.user.username} - {self.projectid} - PID: {self.pid}"


#Share History Table to store share History information.
#Fields : [1] Project(1:M with Project table) [2] User(1:M with MyUser table) [3] Timestamp of Sharing the project [4] Shared User(1:M with MyUser table) [5]Name of the project
#shared_user : To store the list of usernames with whom the project is shared.

class ShareHistory(models.Model):
        project = models.ForeignKey(Project,on_delete=models.CASCADE)
        user = models.ForeignKey(MyUser,on_delete=models.CASCADE)
        timestamp = models.DateTimeField(auto_now_add = True)
        shared_user = models.ForeignKey(MyUser, on_delete = models.CASCADE, related_name="shared_user")
        project_name = models.CharField(max_length = 30, null = False, default="Project Name")

        #Utility Methods
        def __str__(self):
                return self.project.project_name


####################################################################################################
#Project Filter Database for storing filters of each projects

class ProjectFilter(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='filters')
    description = models.BooleanField(default=False)
    cvss_v2 = models.BooleanField(default=False)
    cvss_v3_1 = models.BooleanField(default=False)
    weaknesses = models.BooleanField(default=False)
    references = models.BooleanField(default=False)
    patch_status = models.CharField(max_length=255, null=True, blank=True)
    published_date = models.CharField(max_length=255, null=True, blank=True)
    cvss_v2_base = models.CharField(max_length=255, null=True, blank=True)
    cvss_v2_exploitability =  models.CharField(max_length=255, null=True, blank=True)
    cvss_v2_impact =  models.CharField(max_length=255, null=True, blank=True)
    cvss_v3_1_base =  models.CharField(max_length=255, null=True, blank=True)
    cvss_v3_1_exploitability = models.CharField(max_length=255, null=True, blank=True)
    cvss_v3_1_impact =  models.CharField(max_length=255, null=True, blank=True)
    report_name = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"Filters for {self.project.name}"

from django.utils import timezone


class ProjectModification(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    modification_time = models.DateTimeField(default=timezone.now)
    modification_detail = models.TextField()
    added_rows = models.JSONField(blank=True, null=True)  
    deleted_rows = models.JSONField(blank=True, null=True) 

    def __str__(self):
        return f"{self.user.username} modified {self.project.project_name} on {self.modification_time}"


