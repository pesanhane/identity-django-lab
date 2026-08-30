from .mfa_recovery import generate_recovery_codes

from django.db import transaction
from django.utils import timezone

from .rbac import DynamicPermission

from .models import (
    User,
    AuditLog,
    Role,
    Permission,
    Group,
)

from .serializers import (
    UserSerializer,
    AdminUserUpdateSerializer,
    ChangePasswordSerializer,
    LogoutSerializer,
    RoleSerializer,
    RoleCreateSerializer,
    PermissionSerializer,
    GroupSerializer,
    GroupCreateSerializer,
)

from django.shortcuts import get_object_or_404

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .utils import (
    create_audit_log,
    require_organization,
)


from .mfa import (
    generate_secret,
    generate_totp_uri,
    verify_totp_code_with_counter,
)


# ============================================================
# LISTAR E CRIAR UTILIZADORES
# ==========================================================
class UserList(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        permission_map = {
            "GET": "user.view",
            "POST": "user.create",
        }

        self.permission_required = permission_map.get(
            self.request.method
        )

        return super().get_permissions()

    def get(self, request):

        organization = require_organization(request)

        users = User.objects.filter(
            organization=organization
        )


        serializer = UserSerializer(
            users,
            many=True,
            context={
                "request": request
            }
        )

        return Response(serializer.data)

    def post(self, request):

        organization = require_organization(request)

        serializer = UserSerializer(
            data=request.data,
            context={
                "request": request,
                "organization": organization
            }
        )

        serializer.is_valid(
            raise_exception=True
        )

        user = serializer.save(
            organization=organization
        )

        create_audit_log(
            request,
            "CREATE_USER",
            f"Utilizador {user.username} criado"
        )

        return Response(
            UserSerializer(
                user,
                context={"request": request}
            ).data,
            status=status.HTTP_201_CREATED
        )
# ============================================================
# DETALHE DO UTILIZADOR
# ============================================================
class UserDetail(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        if self.request.method == "GET":
            self.permission_required = "user.view"

        elif self.request.method in ["PUT", "PATCH"]:
            self.permission_required = "user.update"

        elif self.request.method == "DELETE":
            self.permission_required = "user.delete"

        return super().get_permissions()

    def get(self, request, id):

        organization = require_organization(request)

        user = get_object_or_404(
            User,
            id=id,
            organization=organization
        )

        serializer = UserSerializer(
            user,
            context={
                "request": request
            }
        )

        return Response(serializer.data)

    # ==========================================================
    # MÉTODO PRIVADO
    # ==========================================================

    def update_user(self, request, id, partial=False):

        organization = require_organization(request)

        user = get_object_or_404(
            User,
            id=id,
            organization=organization
        )

        serializer = AdminUserUpdateSerializer(
            user,
            data=request.data,
            partial=partial,
            context={
                "request": request
            }
        )

        serializer.is_valid(raise_exception=True)

        username = user.username

        serializer.save()
        
        create_audit_log(
            request,
            "UPDATE_USER",
            f"Atualizou utilizador {username}"
        )

        return Response(serializer.data)

        

    # ==========================================================

    def put(self, request, id):

        return self.update_user(
            request,
            id,
            partial=False
        )

    def patch(self, request, id):

        return self.update_user(
            request,
            id,
            partial=True
        )

    def delete(self, request, id):

        organization = require_organization(request)

        user = get_object_or_404(
            User,
            id=id,
            organization=organization
        )

        username = user.username

        

        create_audit_log(
            request,
            "DELETE_USER",
            f"Eliminou utilizador {username}"
        )

        user.delete()

        return Response(
            status=status.HTTP_204_NO_CONTENT
        )

# ============================================================
# UTILIZADOR AUTENTICADO
# ============================================================

class CurrentUserView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        serializer = UserSerializer(
            request.user,
            context={
                "request": request
            }
        )

        return Response(serializer.data)


# ============================================================
# CONFIGURAÇÃO MFA / TOTP
# ============================================================

class MFASetupView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        user = request.user

        # Gerar segredo apenas se ainda não existir
        if not user.mfa_secret:
            user.mfa_secret = generate_secret()
            user.save(update_fields=["mfa_secret"])

        uri = generate_totp_uri(
            user,
            user.mfa_secret
        )

        create_audit_log(
            request,
            "MFA_SETUP_REQUEST",
            f"Solicitou configuração MFA para {user.username}"
        )

        return Response(
            {
                "mfa_enabled": user.mfa_enabled,
                "otpauth_uri": uri
            },
            status=status.HTTP_200_OK
        )


# ============================================================
# VERIFICAÇÃO E ATIVAÇÃO MFA / TOTP
# ============================================================

class MFAVerifyView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        code = request.data.get("code")

        if not code:
            return Response(
                {
                    "error": "MFA code is required."
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():

            user = (
                User.objects
                .select_for_update()
                .get(pk=request.user.pk)
            )

            if not user.mfa_secret:
                return Response(
                    {
                        "error": (
                            "MFA setup has not been initialized."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            counter = verify_totp_code_with_counter(
                user.mfa_secret,
                code
            )

            if counter is None:

                create_audit_log(
                    request,
                    "MFA_VERIFY_FAILED",
                    f"Falha na verificação MFA de {user.username}"
                )

                return Response(
                    {
                        "error": "Invalid MFA code."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # ==================================================
            # ANTI-REPLAY
            # ==================================================

            if (
                user.mfa_last_used_counter is not None
                and counter <= user.mfa_last_used_counter
            ):

                create_audit_log(
                    request,
                    "MFA_REPLAY_DETECTED",
                    (
                        f"Tentativa de reutilização de código MFA "
                        f"para {user.username}"
                    )
                )

                return Response(
                    {
                        "error": "MFA code has already been used."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # ==================================================
            # ATIVAÇÃO MFA
            # ==================================================

            user.mfa_enabled = True
            user.mfa_verified_at = timezone.now()
            user.mfa_last_used_counter = counter

            user.save(
                update_fields=[
                    "mfa_enabled",
                    "mfa_verified_at",
                    "mfa_last_used_counter",
                ]
            )

            create_audit_log(
                request,
                "MFA_ENABLED",
                f"MFA ativado para {user.username}"
            )

        return Response(
            {
                "message": "MFA enabled successfully.",
                "mfa_enabled": True,
            },
            status=status.HTTP_200_OK
        )
# ============================================================
# ALTERAR PASSWORD
# ============================================================

class ChangePasswordView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        serializer = ChangePasswordSerializer(
            data=request.data
        )

        serializer.is_valid(raise_exception=True)

        user = request.user

        if not user.check_password(
            serializer.validated_data["old_password"]
        ):

            return Response(
                {
                    "error": "Old password incorrect."
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(
            serializer.validated_data["new_password"]
        )

        user.save()

        create_audit_log(
            request,
            "CHANGE_PASSWORD",
            f"Alterou password de {user.username}"
        )

        return Response(
            {
                "message": "Password changed successfully."
            }
        )

# ============================================================
# LOGOUT
# ============================================================

class LogoutView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        serializer = LogoutSerializer(
            data=request.data
        )

        serializer.is_valid(
            raise_exception=True
        )

        refresh_token = serializer.validated_data["refresh"]

        # Auditoria antes da invalidação do token
        create_audit_log(
            request,
            "LOGOUT",
            f"Logout de {request.user.username}"
        )

        # Invalidar refresh token
        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response(
            {
                "message": "Logout successful."
            },
            status=status.HTTP_200_OK
        )

# ============================================================
# AUDITORIA
# ============================================================

class AuditLogView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "audit.view"

        return super().get_permissions()

    def get(self, request):

        organization = require_organization(request)

        logs = (
            AuditLog.objects
            .select_related("user")
            .filter(
                organization=organization
            )
            .order_by("-created_at")
        )

        data = []

        for log in logs:

            data.append({
                "user": (
                    log.user.username
                    if log.user
                    else None
                ),
                "action": log.action,
                "description": log.description,
                "ip": log.ip_address,
                "date": log.created_at,
            })

        return Response(data)

# ============================================================
# ROLE MANAGEMENT
# ============================================================

class RoleListView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "role.manage"

        return super().get_permissions()

    def get(self, request):

        organization = require_organization(request)

        roles = Role.objects.filter(
            organization=organization
        )

        serializer = RoleSerializer(
            roles,
            many=True
        )

        return Response(serializer.data)

    def post(self, request):

        organization = require_organization(
            request
        )

        serializer = RoleCreateSerializer(
            data=request.data,
            context={
                "request": request,
                "organization": organization
            }
        )

        serializer.is_valid(
            raise_exception=True
        )

        role = serializer.save(
            organization=organization
        )

        create_audit_log(
            request,
            "CREATE_ROLE",
            f"Role {role.name} criada"
        )

        return Response(
            RoleSerializer(role).data,
            status=status.HTTP_201_CREATED
        )


class PermissionListView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "role.manage"

        return super().get_permissions()

    def get(self, request):

        permissions = Permission.objects.all()

        serializer = PermissionSerializer(
            permissions,
            many=True
        )

        return Response(serializer.data)

    def post(self, request):

        serializer = PermissionSerializer(
            data=request.data
        )

        serializer.is_valid(
            raise_exception=True
        )

        permission = serializer.save()

        create_audit_log(
            request,
            "CREATE_PERMISSION",
            f"Criou permissão {permission.code}"
        )

        return Response(
            PermissionSerializer(permission).data,
            status=status.HTTP_201_CREATED
        )




class RoleDetailView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "role.manage"

        return super().get_permissions()

    # ==========================================================
    # GET ROLE
    # ==========================================================

    def get(self, request, id):

        organization = require_organization(request)

        role = get_object_or_404(
            Role,
            id=id,
            organization=organization
        )

        return Response(
            RoleSerializer(role).data
        )

    # ==========================================================
    # UPDATE ROLE
    # ==========================================================

    def update_role(
        self,
        request,
        id,
        partial=False
    ):

        organization = require_organization(request)

        role = get_object_or_404(
            Role,
            id=id,
            organization=organization
        )

        serializer = RoleCreateSerializer(
            role,
            data=request.data,
            partial=partial,
            context={
                "request": request,
                "organization": organization
            }
        )

        serializer.is_valid(
            raise_exception=True
        )

        serializer.save()

        create_audit_log(
            request,
            "UPDATE_ROLE",
            f"Atualizou papel {role.name}"
        )

        return Response(
            RoleSerializer(role).data
        )

    # ==========================================================
    # PUT
    # ==========================================================

    def put(self, request, id):

        return self.update_role(
            request,
            id,
            partial=False
        )

    # ==========================================================
    # PATCH
    # ==========================================================

    def patch(self, request, id):

        return self.update_role(
            request,
            id,
            partial=True
        )

    # ==========================================================
    # DELETE
    # ==========================================================

    def delete(self, request, id):

        organization = require_organization(request)

        role = get_object_or_404(
            Role,
            id=id,
            organization=organization
        )

        nome = role.name

        role.delete()

        create_audit_log(
            request,
            "DELETE_ROLE",
            f"Eliminou papel {nome}"
        )

        return Response(
            status=status.HTTP_204_NO_CONTENT
        )


class PermissionDetailView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "role.manage"

        return super().get_permissions()

    def get(self, request, id):

        permission = get_object_or_404(
            Permission,
            id=id
        )

        return Response(
            PermissionSerializer(permission).data
        )

    # ==========================================================
    # MÉTODO PRIVADO
    # ==========================================================

    def update_permission(self, request, id, partial=False):

        permission = get_object_or_404(
            Permission,
            id=id
        )

        serializer = PermissionSerializer(
            permission,
            data=request.data,
            partial=partial
        )

        serializer.is_valid(
            raise_exception=True
        )

        serializer.save()

        create_audit_log(
            request,
            "UPDATE_PERMISSION",
            f"Atualizou permissão {permission.code}"
        )

        return Response(
            PermissionSerializer(permission).data
        )

    # ==========================================================

    def put(self, request, id):

        return self.update_permission(
            request,
            id,
            partial=False
        )

    def patch(self, request, id):

        return self.update_permission(
            request,
            id,
            partial=True
        )

    def delete(self, request, id):

        permission = get_object_or_404(
            Permission,
            id=id
        )

        nome = permission.code

        permission.delete()

        create_audit_log(
            request,
            "DELETE_PERMISSION",
            f"Eliminou permissão {nome}"
        )

        return Response(
            status=status.HTTP_204_NO_CONTENT
        )

# ============================================================
# GROUP MANAGEMENT
# ============================================================

class GroupListView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "group.manage"

        return super().get_permissions()

    # ==========================================================
    # LIST GROUPS
    # ==========================================================

    def get(self, request):

        organization = require_organization(request)

        groups = Group.objects.filter(
            organization=organization
        ).order_by("name")

        serializer = GroupSerializer(
            groups,
            many=True
        )

        return Response(
            serializer.data,
            status=status.HTTP_200_OK
        )

    # ==========================================================
    # CREATE GROUP
    # ==========================================================

    def post(self, request):

        organization = require_organization(request)

        serializer = GroupCreateSerializer(
            data=request.data,
            context={
                "request": request,
                "organization": organization,
            }
        )

        serializer.is_valid(
            raise_exception=True
        )

        group = serializer.save(
            organization=organization
        )

        create_audit_log(
            request,
            "CREATE_GROUP",
            f"Criou grupo {group.name}"
        )

        return Response(
            GroupSerializer(group).data,
            status=status.HTTP_201_CREATED
        )


# ============================================================
# GROUP DETAIL
# ============================================================

class GroupDetailView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "group.manage"

        return super().get_permissions()

    # ==========================================================
    # GET GROUP
    # ==========================================================

    def get(self, request, id):

        organization = require_organization(request)

        group = get_object_or_404(
            Group,
            id=id,
            organization=organization
        )

        return Response(
            GroupSerializer(group).data,
            status=status.HTTP_200_OK
        )

    # ==========================================================
    # UPDATE GROUP
    # ==========================================================

    def update_group(
        self,
        request,
        id,
        partial=False
    ):

        organization = require_organization(request)

        group = get_object_or_404(
            Group,
            id=id,
            organization=organization
        )

        serializer = GroupCreateSerializer(
            group,
            data=request.data,
            partial=partial,
            context={
                "request": request,
                "organization": organization,
            }
        )

        serializer.is_valid(
            raise_exception=True
        )

        serializer.save()

        create_audit_log(
            request,
            "UPDATE_GROUP",
            f"Atualizou grupo {group.name}"
        )

        return Response(
            GroupSerializer(group).data,
            status=status.HTTP_200_OK
        )

    # ==========================================================
    # PUT
    # ==========================================================

    def put(self, request, id):

        return self.update_group(
            request,
            id,
            partial=False
        )

    # ==========================================================
    # PATCH
    # ==========================================================

    def patch(self, request, id):

        return self.update_group(
            request,
            id,
            partial=True
        )

    # ==========================================================
    # DELETE
    # ==========================================================

    def delete(self, request, id):

        organization = require_organization(request)

        group = get_object_or_404(
            Group,
            id=id,
            organization=organization
        )

        name = group.name

        group.delete()

        create_audit_log(
            request,
            "DELETE_GROUP",
            f"Eliminou grupo {name}"
        )

        return Response(
            status=status.HTTP_204_NO_CONTENT
        )


class ActivateUserView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "user.activate"

        return super().get_permissions()

    def post(self, request, id):

        organization = require_organization(request)

        user = get_object_or_404(
            User,
            id=id,
            organization=organization
        )

        user.is_active = True

        user.save(
            update_fields=["is_active"]
        )

        create_audit_log(
            request,
            "ACTIVATE_USER",
            f"Ativou utilizador {user.username}"
        )

        return Response({
            "message": "Utilizador ativado com sucesso.",
            "user": user.username,
            "is_active": user.is_active
        })



class DeactivateUserView(APIView):

    permission_classes = [DynamicPermission]

    def get_permissions(self):

        self.permission_required = "user.deactivate"

        return super().get_permissions()

    def post(self, request, id):

        organization = require_organization(request)

        user = get_object_or_404(
            User,
            id=id,
            organization=organization
        )

        if user.id == request.user.id:

            return Response(
                {
                    "error": "Não pode desativar a própria conta."
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        user.is_active = False

        user.save(
            update_fields=["is_active"]
        )

        create_audit_log(
            request,
            "DEACTIVATE_USER",
            f"Desativou utilizador {user.username}"
        )

        return Response({
            "message": "Utilizador desativado com sucesso.",
            "user": user.username,
            "is_active": user.is_active
        })

# ============================================================
# MFA RECOVERY CODES
# ============================================================

class MFARecoveryCodesView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        user = request.user

        if not user.mfa_enabled:
            return Response(
                {
                    "error": "MFA must be enabled before generating recovery codes."
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        codes = generate_recovery_codes(user)

        create_audit_log(
            request,
            "MFA_RECOVERY_CODES_GENERATED",
            f"Recovery codes gerados para {user.username}"
        )

        return Response(
            {
                "message": "Recovery codes generated successfully.",
                "recovery_codes": codes,
            },
            status=status.HTTP_200_OK
        )