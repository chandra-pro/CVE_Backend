from django.db.models import Q
from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm
import re
from .models import MyUser
import logging
import ldap

User = get_user_model()
logger = logging.getLogger(__name__)

class PasswordChangeFormNew(PasswordResetForm):
    """
       This class creates a Password Reset Form for the user.
    """

    def clean_email(self):
        """
           This method checks the existence of email in the database.
        """
        email = self.cleaned_data['email']
        if not User.objects.filter(email__iexact=email, is_active=True).exists():
            logger.error(f"PasswordChangeFormNew: No user registered with email - {email}")
            raise forms.ValidationError("There is no user registered with the specified E-Mail address.")
        return email

class ProjectChangeForm(forms.Form):
    """
       This class creates a Modify Form for the project to get updated.
    """
    project_name = forms.CharField()
    xml_path = forms.FileField()
    build_file = forms.FileField()

class UserLoginForm(forms.Form):
    """
    Updated form for validating user login.
    """
    query = forms.CharField()
    password = forms.CharField()

    def clean(self):
        """
        Validates the login process:
        1. Checks if the user exists in the database.
        2. If the user does not exist or has no password set, authenticates via LDAP.
        3. If LDAP authentication succeeds, creates the user in the database if they don’t exist.
        """
        query = self.cleaned_data.get('query')
        password = self.cleaned_data.get('password')
        user_obj = None

        logger.info(f"Login attempt for: {query}")

        # Query the database for the user first
        user_qs_final = User.objects.filter(
            Q(username__iexact=query) |
            Q(email__iexact=query)
        ).distinct()

        if user_qs_final.exists() and user_qs_final.count() == 1:
            user_obj = user_qs_final.first()

            if user_obj.has_usable_password() and user_obj.check_password(password):
                logger.info(f"Authenticated via local database: {query}")
                self.cleaned_data['user_obj'] = user_obj
                return super().clean()
            else:
                # Attempt LDAP authentication for existing users without passwords
                ldap_authenticated = self.ldap_authenticate(query, password)
                if ldap_authenticated:
                    logger.info(f"Authenticated via LDAP for existing user: {query}")
                    self.cleaned_data['user_obj'] = user_obj
                    return super().clean()
        else:
            # Perform LDAP authentication if the user is not found in the database
            ldap_authenticated = self.ldap_authenticate(query, password)
            if ldap_authenticated:
                logger.info(f"Authenticated via LDAP for new user: {query}")
                self.cleaned_data['user_obj'] = ldap_authenticated
                return super().clean()

        logger.warning(f"Failed login attempt for: {query}")
        raise forms.ValidationError("Invalid login credentials.")

    def ldap_authenticate(self, query, password):
        """
        Authenticates the user via LDAP and saves the user in the database if authentication is successful.
        """
        AUTH_LDAP_SERVER_URI = 'ldap://ldap.inn.mentorg.com:389'
        if query and password:
            try:
                base_dn = "dc=mgc,dc=mentorg,dc=com"
                ldap_obj = ldap.initialize(AUTH_LDAP_SERVER_URI)
                ldap_obj.set_option(ldap.OPT_REFERRALS, 0)
                ldap_obj.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

                user_name = f"mgc\\{query}"
                ldap_obj.simple_bind_s(user_name, password)

                # Perform LDAP search to retrieve user information
                search_filter = f"(sAMAccountName={query})"
                search_attribute = ['mail', 'title', 'displayName', 'cn', 'extensionAttribute11']
                ldap_user_info = ldap_obj.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter, search_attribute)

                if ldap_user_info:
                    user_info = ldap_user_info[0][1]
                    email = user_info['mail'][0].decode("utf-8")
                    title = user_info['title'][0].decode("utf-8")
                    name = user_info['displayName'][0].decode("utf-8")
                    username = user_info['cn'][0].decode("utf-8")

                    first_name, last_name = name.split(' ', 1) if ' ' in name else (name, '')

                    # Update cleaned data
                    self.cleaned_data.update({
                        "email": email,
                        "title": title,
                        "first_name": first_name,
                        "last_name": last_name,
                        "username": username,
                        "photo": user_info.get('extensionAttribute11', [b""])[0].decode("utf-8"),
                    })

                    # Create or update the user in the database
                    user_obj, created = User.objects.update_or_create(
                        username=username,
                        defaults={
                            'email': email,
                            'is_active': True,
                        }
                    )
                    if created:
                        user_obj.set_unusable_password()  # LDAP users don't need a local password
                    user_obj.save()

                    self.cleaned_data['user_obj'] = user_obj
                    return user_obj
            except ldap.INVALID_CREDENTIALS:
                logger.error(f"Invalid LDAP credentials for user: {query}")
                raise forms.ValidationError("Invalid LDAP credentials.")
            except Exception as e:
                logger.error(f"LDAP error for user {query}: {e}")
                raise forms.ValidationError(f"An error occurred during LDAP authentication: {e}")

        raise forms.ValidationError("Invalid login credentials.")
class UserCreationForm(forms.ModelForm):
    """
       This class is used to create a Signup Form.
    """
    username = forms.CharField(label='Username', widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Your Username'
    }))
    email = forms.EmailField(label='Email', widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Your Email Address',
    }))
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput(attrs={
        'class': 'form-control',
        'placeholder': 'Password',
    }))
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput(attrs={
        'class': 'form-control',
        'placeholder': 'Confirm Password',
    }))

    class Meta:
        model = User
        fields = ('username', 'email')

    def clean_email(self):
        """
            This method checks the uniqueness of email.
        """
        email = self.cleaned_data['email']
        if User.objects.filter(email__iexact=email, is_active=True).exists():
            logger.error(f"This E-Mail address - {email} already exists")
            raise forms.ValidationError("This E-Mail address already exists.")
        return email

    def clean_password2(self):
        """
           This method checks that the two password entries match.
        """
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        
        pattern = re.compile("^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$")
        if not pattern.search(password2):
            raise forms.ValidationError("Invalid Password format")
        return password2

    def save(self, commit=True):
        """
           This method saves the provided password in hashed format.
        """
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class UserChangeForm(forms.ModelForm):
    """
       A form for updating users. Includes all the fields on the user, but replaces the password field with admin's password hash display field.
    """
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'is_staff', 'is_active')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        return self.initial["password"]

