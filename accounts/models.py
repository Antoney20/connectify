from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Group

class UserProfileManager(BaseUserManager):
    def create_user(self, username, email, password=None, role='user', **extra_fields):
        if not username:
            raise ValueError('The Username field must be set')
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)

        # Create user instance
        user = self.model(username=username, email=email, role=role, **extra_fields)
        user.set_password(password)

        # Assign user to appropriate group based on role without multiple saves
        user_group_mapping = {
            'admin': 'Admins',
            'agent': 'Agents',
            'user': 'Users'
        }
        group_name = user_group_mapping.get(role, 'Users')
        group, _ = Group.objects.get_or_create(name=group_name)
        
        user.save(using=self._db)  # Save user to get primary key
        user.groups.add(group)  # Add to group after saving

        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(username, email, password, role='admin', **extra_fields)

    def assign_role(self, user, role):
        """
        Assigns a role to a user profile and updates group membership.
        """
        user_group_mapping = {
            'admin': 'Admins',
            'agent': 'Agents',
            'user': 'Users'
        }
        if role not in user_group_mapping:
            raise ValueError('Invalid role')

        group_name = user_group_mapping[role]
        new_group, _ = Group.objects.get_or_create(name=group_name)

        # Remove user from old groups and add to the new group
        user.groups.clear()
        user.groups.add(new_group)
        
        user.role = role
        user.save(using=self._db)

class UserProfile(AbstractBaseUser, PermissionsMixin):
    
    ROLE_CHOICES = [
        ('user', 'User'),
        ('agent', 'Agent'),
        ('admin', 'Admin'),
    ]
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    otp_expiration = models.DateTimeField(null=True, blank=True)
    interests = models.TextField()
    
    # Custom related names to resolve clash
    groups = models.ManyToManyField(Group, related_name='user_profiles')
    user_permissions = models.ManyToManyField('auth.Permission', related_name='user_profiles')

    objects = UserProfileManager()

    USERNAME_FIELD = 'email'  
    REQUIRED_FIELDS = ['username'] 

    def __str__(self):
        return self.username
