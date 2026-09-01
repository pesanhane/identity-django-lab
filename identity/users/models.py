from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
import uuid








class Permission(models.Model):

    code = models.CharField(
        max_length=100,
        unique=True
    )

    description = models.CharField(
        max_length=255
    )

    def __str__(self):
        return self.code

class Organization(models.Model):

    name = models.CharField(
        max_length=100,
        unique=True
    )

    description = models.CharField(
        max_length=255,
        blank=True
    )

    is_active = models.BooleanField(
        default=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    def __str__(self):
        return self.name


class Group(models.Model):

    name = models.CharField(
        max_length=100
    )

    description = models.CharField(
        max_length=255,
        blank=True
    )

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="groups"
    )

    is_active = models.BooleanField(
        default=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                name="unique_group_per_organization"
            )
        ]

    def __str__(self):
        return self.name

class Role(models.Model):

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="roles",
        null=True,
        blank=True   
    )

    name = models.CharField(
        max_length=50
    )

    description = models.CharField(
        max_length=255,
        blank=True
    )

    permissions = models.ManyToManyField(
        Permission,
        blank=True,
        related_name="roles"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                name="unique_role_per_organization"
            )
        ]

    def __str__(self):
        return self.name

class User(AbstractUser):
    """
    Custom User model for Identity Management System.
    Extends Django default user with roles and audit information.
    """

    

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="users"
    )

    roles = models.ManyToManyField(
        Role,
        blank=True,
        related_name="users"
    )

    iam_groups = models.ManyToManyField(
        "Group",
        blank=True,
        related_name="users"
    )



    phone_number = models.CharField(
        max_length=20,
        blank=True,
        null=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    last_login_ip = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    is_verified = models.BooleanField(
        default=False
    )

    mfa_enabled = models.BooleanField(
        default=False
    )

    mfa_secret = models.CharField(
        max_length=64,
        blank=True,
        null=True
    )

    mfa_verified_at = models.DateTimeField(
        null=True,
        blank=True
    )

    mfa_last_used_counter = models.BigIntegerField(
        null=True,
        blank=True
    )

    
    def __str__(self):
        return self.username


class AuditLog(models.Model):

    organization = models.ForeignKey(
        Organization,
        on_delete=models.PROTECT,
        related_name="audit_logs"
    )

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs"
    )

    action = models.CharField(
        max_length=50
    )

    description = models.TextField()

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    endpoint = models.CharField(
        max_length=255,
        null=True,
        blank=True
    )

    http_method = models.CharField(
        max_length=10,
        null=True,
        blank=True
    )

    object_id = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )

    object_type = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )

    result = models.CharField(
        max_length=20,
        null=True,
        blank=True
    )

    status_code = models.IntegerField(
        null=True,
        blank=True
    )

    user_agent = models.TextField(
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

class MFARecoveryCode(models.Model):
    """
    Código de recuperação MFA de uso único.

    O código em texto puro nunca é armazenado.
    Apenas o hash é persistido.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="mfa_recovery_codes"
    )

    code_hash = models.CharField(
        max_length=128
    )

    used_at = models.DateTimeField(
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        status = (
            "used"
            if self.used_at
            else "unused"
        )

        return (
            f"MFA recovery code "
            f"for {self.user.username} "
            f"({status})"
        )

    @property
    def is_used(self):
        return self.used_at is not None


class UserSession(models.Model):

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="active_sessions",
    )

    jti = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
    )

    device_name = models.CharField(
        max_length=255,
        blank=True,
    )

    user_agent = models.TextField(
        blank=True,
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    last_activity = models.DateTimeField(
        auto_now=True,
    )

    expires_at = models.DateTimeField()

    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    @property
    def is_revoked(self):
        return self.revoked_at is not None

    def __str__(self):
        return (
            f"{self.user.username} - "
            f"{self.device_name or 'Unknown device'}"
        )