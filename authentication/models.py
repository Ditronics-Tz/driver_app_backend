from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.utils import timezone
from datetime import timedelta
import random
import string
import uuid

class UserManager(BaseUserManager):
    """Custom user manager for email/phone authentication"""
    
    def create_user(self, email=None, phone_number=None, password=None, **extra_fields):
        if not email and not phone_number:
            raise ValueError('User must have either email or phone number')

        extra_fields.pop('username', None)
        
        if email:
            email = self.normalize_email(email)
        
        user = self.model(
            email=email,
            phone_number=phone_number,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email=None, phone_number=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, phone_number, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User Model for Driver App Authentication"""
    
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    
    # UUID field for public API usage
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=False, db_index=True)
    
    # Basic Information
    email = models.EmailField(unique=True, null=True, blank=True)
    phone_number = models.CharField(
        validators=[phone_regex], 
        max_length=17, 
        unique=True, 
        null=True, 
        blank=True
    )
    full_name = models.CharField(max_length=255)
    
    # Authentication fields
    is_active = models.BooleanField(default=False)  # Will be activated after OTP verification
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    STATUS_ACTIVE = "active"
    STATUS_SUSPENDED = "suspended"
    STATUS_BANNED = "banned"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_SUSPENDED, "Suspended"),
        (STATUS_BANNED, "Banned"),
    ]

    account_status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    
    # Verification fields
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    
    # Timestamps
    date_joined = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']
    
    class Meta:
        db_table = 'authentication_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email'], name='user_email_idx'),
            models.Index(fields=['phone_number'], name='user_phone_idx'),
            models.Index(fields=['uuid'], name='user_uuid_idx'),
            models.Index(fields=['is_active', 'email'], name='user_active_email_idx'),
            models.Index(fields=['is_active', 'phone_number'], name='user_active_phone_idx'),
        ]
        
    def __str__(self):
        return self.email or self.phone_number or f"User {self.uuid}"
    
    def get_full_name(self):
        return self.full_name
    
    def get_short_name(self):
        return self.full_name.split(' ')[0] if self.full_name else ''


class OTPVerification(models.Model):
    """Model for OTP verification"""
    
    OTP_TYPES = [
        ('email', 'Email Verification'),
        ('phone', 'Phone Verification'),
        ('password_reset', 'Password Reset'),
        ('login', 'Login Verification'),
    ]
    
    # UUID field for public API usage
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=False, db_index=True)
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otp_verifications')
    otp_code = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPES)
    recipient = models.CharField(max_length=100)  # email or phone number
    
    # Tracking fields
    is_verified = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    
    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'authentication_otp_verification'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'otp_type', 'is_verified'], name='otp_user_type_verified_idx'),
            models.Index(fields=['recipient', 'otp_type'], name='otp_recipient_type_idx'),
            models.Index(fields=['user', 'is_verified', '-created_at'], name='otp_user_latest_idx'),
            models.Index(fields=['expires_at'], name='otp_expires_idx'),
        ]
        
    def __str__(self):
        return f"OTP for {self.user} - {self.otp_type}"
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            from django.conf import settings
            expiry_minutes = getattr(settings, 'OTP_EXPIRY_MINUTES', 10)
            self.expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def can_attempt(self):
        return self.attempts < self.max_attempts and not self.is_expired() and not self.is_verified
    
    def verify_otp(self, provided_otp):
        """Verify the provided OTP"""
        if not self.can_attempt():
            return False, "OTP has expired, exceeded attempts, or already verified"
        
        self.attempts += 1
        self.save()
        
        if self.otp_code == provided_otp:
            self.is_verified = True
            self.verified_at = timezone.now()
            self.save()
            
            # Update user verification status
            if self.otp_type == 'email':
                self.user.email_verified = True
                self.user.is_active = True
            elif self.otp_type == 'phone':
                self.user.phone_verified = True
                self.user.is_active = True
            
            self.user.save()
            return True, "OTP verified successfully"
        
        return False, f"Invalid OTP. {self.max_attempts - self.attempts} attempts remaining"
    
    @classmethod
    def generate_otp(cls, user, otp_type, recipient):
        """Generate a new OTP for user"""
        from django.conf import settings
        
        # Deactivate previous OTPs of same type
        cls.objects.filter(
            user=user, 
            otp_type=otp_type, 
            recipient=recipient,
            is_verified=False
        ).update(is_verified=True)
        
        # Generate new OTP
        otp_length = getattr(settings, 'OTP_LENGTH', 4)
        otp_code = ''.join(random.choices(string.digits, k=otp_length))
        
        otp_verification = cls.objects.create(
            user=user,
            otp_code=otp_code,
            otp_type=otp_type,
            recipient=recipient
        )
        
        return otp_verification


class UserSession(models.Model):
    """Track user login sessions"""
    
    # UUID field for public API usage
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=False, db_index=True)
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_info = models.JSONField(default=dict, blank=True)
    
    # Timestamps
    login_at = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(default=timezone.now)
    logout_at = models.DateTimeField(null=True, blank=True)
    
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'authentication_user_session'
        ordering = ['-login_at']
        
    def __str__(self):
        return f"Session for {self.user} from {self.ip_address}"
