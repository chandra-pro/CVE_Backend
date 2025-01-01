from rest_framework import serializers
from .models import MyUser, Profile, Project, XML, Permission
from django.contrib.auth import get_user_model

MyUser = get_user_model()

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['first_name', 'last_name', 'title', 'photo']

class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer()  # Nesting the ProfileSerializer

    class Meta:
        model = MyUser
        fields = ['username', 'email', 'is_active', 'is_staff', 'profile']

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', None)
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.is_staff = validated_data.get('is_staff', instance.is_staff)
        instance.save()

        if profile_data:
            profile, created = Profile.objects.update_or_create(user=instance, defaults=profile_data)

        return instance

class XMLSerializer(serializers.ModelSerializer):
    class Meta:
        model = XML
        fields = [
            'project_version', 'tool_use', 'xml_path', 'source_path',
            'build_file', 'diff_csv', 'diff_file_version',
            'github_link', 'branch', 'upstream_branch', 'dot_kernel_branch','kernel_version'
        ]

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['write', 'user', 'permission_timestamp']

class ProjectSerializer(serializers.ModelSerializer):
    xml_data = XMLSerializer(source='xmls', many=True, required=False)
    permissions = PermissionSerializer(source='permission', many=True, required=False)
    user = serializers.PrimaryKeyRelatedField(many=True, queryset=MyUser.objects.all())
    real_owner = serializers.CharField(read_only=True)

    class Meta:
        model = Project
        fields = ['id', 'project_name', 'user', 'xml_data', 'permissions','real_owner']

    def create(self, validated_data):
        user_data = validated_data.pop('user', None)
        xml_data = validated_data.pop('xmls', None)
        permissions_data = validated_data.pop('permission', None)

        project = Project.objects.create(**validated_data)
        if user_data:
            project.user.set(user_data)  # Set the many-to-many relationship

        if xml_data:
            for xml_item in xml_data:
                XML.objects.create(project=project, **xml_item)

        if permissions_data:
            for perm_item in permissions_data:
                Permission.objects.create(project=project, **perm_item)

        return project

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', None)
        xml_data = validated_data.pop('xmls', None)
        permissions_data = validated_data.pop('permission', None)

        instance.project_name = validated_data.get('project_name', instance.project_name)
        instance.save()

        if user_data:
            instance.user.set(user_data)  # Update many-to-many relationship

        if xml_data:
            for xml_item in xml_data:
                xml_instance, created = XML.objects.update_or_create(
                    project=instance,
                    defaults=xml_item
                )

        if permissions_data:
            for perm_item in permissions_data:
                perm_instance, created = Permission.objects.update_or_create(
                    project=instance,
                    user=perm_item.get('user'),
                    defaults=perm_item
                )
        return instance

