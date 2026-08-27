from rest_framework import serializers

from .models import (
    User,
    Role,
    Permission,
    Group,
)

from django.contrib.auth.password_validation import validate_password

from rest_framework_simplejwt.tokens import RefreshToken


# ============================================================
# USER SERIALIZER
# ============================================================

class UserSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        write_only=True,
        required=True
    )

    roles = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Role.objects.all(),
        required=False
    )

    class Meta:

        model = User

        fields = [
            "id",
            "username",
            "email",
            "password",
            "first_name",
            "last_name",
            "roles",
            "phone_number",
            "organization",
            "is_verified",
            "is_active",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "organization",
            "created_at",
        ]

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        request = self.context.get("request")

        if (
            request
            and request.user.is_authenticated
            and request.user.organization
        ):

            self.fields["roles"].queryset = Role.objects.filter(
                organization=request.user.organization
            )

    def create(self, validated_data):

        password = validated_data.pop("password")

        roles = validated_data.pop("roles", [])

        user = User.objects.create_user(
            password=password,
            **validated_data
        )

        user.roles.set(roles)

        return user

# ============================================================
# USER UPDATE
# ============================================================

class UserUpdateSerializer(
    serializers.ModelSerializer
):

    class Meta:

        model = User

        fields = [
            "username",
            "email",
            "first_name",
            "last_name",
            "phone_number",
        ]


# ============================================================
# ADMIN USER UPDATE
# ============================================================

class AdminUserUpdateSerializer(
    serializers.ModelSerializer
):

    roles = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Role.objects.all(),
        required=False
    )

    class Meta:

        model = User

        fields = [
            "username",
            "email",
            "first_name",
            "last_name",
            "phone_number",
            "roles",
            "is_verified",
        ]

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        request = self.context.get("request")

        if request and request.user.is_authenticated:

            organization = request.user.organization

            if organization:

                self.fields["roles"].queryset = Role.objects.filter(
                    organization=organization
                )

    def validate_roles(self, roles):

        request = self.context.get("request")

        if request is None:
            raise serializers.ValidationError(
                "Request não disponível."
            )

        organization = request.user.organization

        if organization is None:
            raise serializers.ValidationError(
                "Utilizador não pertence a uma organização."
            )

        invalid_roles = [
            role.name
            for role in roles
            if role.organization_id != organization.id
        ]

        if invalid_roles:

            raise serializers.ValidationError(
                "Uma ou mais roles não pertencem à organização atual."
            )

        return roles


# ============================================================
# CHANGE PASSWORD
# ============================================================

class ChangePasswordSerializer(
    serializers.Serializer
):

    old_password = serializers.CharField(
        write_only=True
    )

    new_password = serializers.CharField(
        write_only=True
    )

    def validate_new_password(self, value):

        validate_password(value)

        old_password = self.initial_data.get(
            "old_password"
        )

        if (
            old_password
            and old_password == value
        ):
            raise serializers.ValidationError(
                "A nova palavra-passe não pode ser igual à palavra-passe antiga."
            )

        return value


# ============================================================
# LOGOUT
# ============================================================

class LogoutSerializer(serializers.Serializer):

    refresh = serializers.CharField()


# ============================================================
# RBAC
# ============================================================

class PermissionSerializer(
    serializers.ModelSerializer
):

    class Meta:

        model = Permission

        fields = [
            "id",
            "code",
            "description",
        ]


# ============================================================
# ROLE READ
# ============================================================

class RoleSerializer(
    serializers.ModelSerializer
):

    permissions = PermissionSerializer(
        many=True,
        read_only=True
    )

    class Meta:

        model = Role

        fields = [
            "id",
            "name",
            "description",
            "permissions",
            "organization",
        ]

        read_only_fields = [
            "id",
            "organization",
        ]


# ============================================================
# ROLE CREATE / UPDATE
# ============================================================

class RoleCreateSerializer(
    serializers.ModelSerializer
):

    permissions = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Permission.objects.all()
    )

    class Meta:

        model = Role

        fields = [
            "name",
            "description",
            "permissions",
        ]
    def validate_name(self, value):

        organization = self.context.get(
            "organization"
        )

        if organization is None:
            raise serializers.ValidationError(
                "Organização não identificada."
            )

        queryset = Role.objects.filter(
            organization=organization,
            name=value
        )

        if self.instance:
            queryset = queryset.exclude(
                pk=self.instance.pk
            )

        if queryset.exists():
            raise serializers.ValidationError(
                "Já existe uma role com este nome nesta organização."
            )

        return value

# ============================================================
# GROUP READ
# ============================================================

class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group

        fields = [
            "id",
            "name",
            "description",
            "organization",
            "is_active",
            "created_at",
            "updated_at",
        ]

        read_only_fields = [
            "id",
            "organization",
            "created_at",
            "updated_at",
        ]


# ============================================================
# GROUP CREATE / UPDATE
# ============================================================

class GroupCreateSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group

        fields = [
            "name",
            "description",
            "is_active",
        ]

    def validate_name(self, value):

        organization = self.context.get("organization")

        if organization is None:
            raise serializers.ValidationError(
                "Organização não identificada."
            )

        queryset = Group.objects.filter(
            organization=organization,
            name=value
        )

        if self.instance:
            queryset = queryset.exclude(
                pk=self.instance.pk
            )

        if queryset.exists():
            raise serializers.ValidationError(
                "Já existe um grupo com este nome nesta organização."
            )

        return value