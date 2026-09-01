
from django.db import transaction
from django.utils import timezone

from .rbac import DynamicPermission
from rest_framework.exceptions import Throttled
from .authentication import apply_mfa_rate_limit

from .models import (
    User,
    AuditLog,
    Role,
    Permission,
    Group,
    MFARecoveryCode,
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
from .models import UserSession
from rest_framework.exceptions import NotFound
from rest_framework_simplejwt.exceptions import TokenError

from .utils import (
    create_audit_log,
    require_organization,
)


from .mfa import (
    generate_secret,
    generate_totp_uri,
    verify_totp_code_with_counter,
)

from .mfa_recovery import generate_recovery_codes

from .session_management import (
    blacklist_user_session,
)

from rest_framework_simplejwt.exceptions import TokenError


# ============================================================
# LISTAR E CRIAR UTILIZADORES
# ==========================================================
# imports
from rest_framework.exceptions import Throttled



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

def apply_mfa_disable_rate_limit(
    request,
    user,
):
    """
    Aplica rate limiting às tentativas falhadas
    de desativação do MFA.

    Retorna True quando o limite foi atingido.
    Retorna False caso a tentativa ainda esteja
    dentro do limite.
    """

    try:

        apply_mfa_rate_limit(
            request,
            user.username,
        )

        return False

    except Throttled:

        create_audit_log(
            request,
            "MFA_DISABLE_RATE_LIMITED",
            (
                "Desativação MFA bloqueada "
                "por excesso de tentativas."
            ),
            status_code=429,
            result="FAILURE",
        )

        return True

class MFADisableView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        user = request.user

        # ======================================================
        # MFA MUST BE ENABLED
        # ======================================================

        if not user.mfa_enabled:

            return Response(
                {
                    "error": (
                        "MFA is not enabled for this user."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        password = request.data.get(
            "password"
        )

        code = request.data.get(
            "code"
        )

        # ======================================================
        # PASSWORD REQUIRED
        # ======================================================

        if not password:

            create_audit_log(
                request,
                "MFA_DISABLE_FAILED",
                (
                    "Desativação MFA recusada: "
                    "password ausente."
                ),
                status_code=400,
                result="FAILURE",
            )

            return Response(
                {
                    "password": (
                        "Current password is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ======================================================
        # TOTP REQUIRED
        # ======================================================

        if not code:

            create_audit_log(
                request,
                "MFA_DISABLE_FAILED",
                (
                    "Desativação MFA recusada: "
                    "código MFA ausente."
                ),
                status_code=400,
                result="FAILURE",
            )

            return Response(
                {
                    "code": (
                        "MFA code is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ======================================================
        # STRONG REAUTHENTICATION
        # ======================================================

        with transaction.atomic():

            locked_user = (
                User.objects
                .select_for_update()
                .get(pk=user.pk)
            )

            # --------------------------------------------------
            # PASSWORD VALIDATION
            # --------------------------------------------------

            if not locked_user.check_password(
                password
            ):

                rate_limited = (
                    apply_mfa_disable_rate_limit(
                        request,
                        locked_user,
                    )
                )

                if rate_limited:

                    return Response(
                        {
                            "detail": (
                                "Too many failed MFA disable attempts. "
                                "Try again later."
                            )
                        },
                        status=status.HTTP_429_TOO_MANY_REQUESTS,
                    )

                create_audit_log(
                    request,
                    "MFA_DISABLE_FAILED",
                    (
                        "Desativação MFA recusada: "
                        "password inválida."
                    ),
                    status_code=400,
                    result="FAILURE",
                )

                return Response(
                    {
                        "password": (
                            "Invalid current password."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # --------------------------------------------------
            # MFA SECRET
            # --------------------------------------------------

            if not locked_user.mfa_secret:

                create_audit_log(
                    request,
                    "MFA_DISABLE_FAILED",
                    (
                        "Desativação MFA recusada: "
                        "secret MFA inexistente."
                    ),
                    status_code=400,
                    result="FAILURE",
                )

                return Response(
                    {
                        "code": (
                            "MFA configuration is invalid."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # --------------------------------------------------
            # VERIFY TOTP
            # --------------------------------------------------

            counter = (
                verify_totp_code_with_counter(
                    locked_user.mfa_secret,
                    code,
                )
            )
            if counter is None:

                rate_limited = (
                    apply_mfa_disable_rate_limit(
                        request,
                        locked_user,
                    )
                )

                if rate_limited:

                    return Response(
                        {
                            "detail": (
                                "Too many failed MFA disable attempts. "
                                "Try again later."
                            )
                        },
                        status=status.HTTP_429_TOO_MANY_REQUESTS,
                    )

                create_audit_log(
                    request,
                    "MFA_DISABLE_FAILED",
                    (
                        "Desativação MFA recusada: "
                        "código MFA inválido."
                    ),
                    status_code=400,
                    result="FAILURE",
                )

                return Response(
                    {
                        "code": (
                            "Invalid MFA code."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # --------------------------------------------------
            # ANTI-REPLAY
            # --------------------------------------------------
            if (
                    locked_user.mfa_last_used_counter
                    is not None
                    and
                    counter <= locked_user.mfa_last_used_counter
                ):

                    rate_limited = (
                        apply_mfa_disable_rate_limit(
                            request,
                            locked_user,
                        )
                    )

                    if rate_limited:

                        return Response(
                            {
                                "detail": (
                                    "Too many failed MFA disable attempts. "
                                    "Try again later."
                                )
                            },
                            status=status.HTTP_429_TOO_MANY_REQUESTS,
                        )

                    create_audit_log(
                        request,
                        "MFA_DISABLE_REPLAY_DETECTED",
                        (
                            "Tentativa de desativação MFA "
                            "com código TOTP reutilizado."
                        ),
                        status_code=400,
                        result="FAILURE",
                    )

                    return Response(
                        {
                            "code": (
                                "MFA code has already been used."
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            

            # ==================================================
            # DISABLE MFA
            # ==================================================

            locked_user.mfa_enabled = False
            locked_user.mfa_secret = None
            locked_user.mfa_verified_at = None
            locked_user.mfa_last_used_counter = None

            locked_user.save(
                update_fields=[
                    "mfa_enabled",
                    "mfa_secret",
                    "mfa_verified_at",
                    "mfa_last_used_counter",
                ]
            )

            # ==================================================
            # INVALIDATE ALL RECOVERY CODES
            # ==================================================

            MFARecoveryCode.objects.filter(
                user=locked_user
            ).delete()

        # ======================================================
        # AUDIT SUCCESS
        # ======================================================

        create_audit_log(
            request,
            "MFA_DISABLED",
            (
                f"MFA desativado para "
                f"{user.username}."
            ),
            status_code=200,
            result="SUCCESS",
        )

        return Response(
            {
                "message": (
                    "MFA disabled successfully."
                )
            },
            status=status.HTTP_200_OK,
        )


class MFAStatusView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        user = request.user

        recovery_codes = (
            MFARecoveryCode.objects
            .filter(user=user)
        )

        total_codes = recovery_codes.count()

        unused_codes = recovery_codes.filter(
            used_at__isnull=True
        ).count()

        used_codes = total_codes - unused_codes

        return Response(
            {
                "mfa_enabled": user.mfa_enabled,
                "mfa_verified_at": user.mfa_verified_at,
                "recovery_codes": {
                    "total": total_codes,
                    "unused": unused_codes,
                    "used": used_codes,
                },
            },
            status=status.HTTP_200_OK,
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

        refresh_token = request.data.get(
            "refresh"
        )

        if not refresh_token:
            return Response(
                {
                    "detail": (
                        "Refresh token is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:

            token = RefreshToken(
                refresh_token
            )

            session_id = token.get(
                "session_id"
            )

            # Garante que o refresh token pertence
            # ao utilizador autenticado.
            token_user_id = token.get(
                "user_id"
            )

            if str(token_user_id) != str(
                request.user.id
            ):
                return Response(
                    {
                        "detail": (
                            "Refresh token does not "
                            "belong to the authenticated user."
                        )
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Revoga o refresh token no
            # mecanismo nativo do SimpleJWT.
            token.blacklist()

            # Tokens antigos podem não possuir
            # session_id.
            if session_id:

                UserSession.objects.filter(
                    id=session_id,
                    user=request.user,
                    revoked_at__isnull=True,
                ).update(
                    revoked_at=timezone.now()
                )

            # Auditoria do logout
            # Auditoria apenas quando o utilizador
            # pertence a uma organização.
            if getattr(
                request.user,
                "organization",
                None,
            ) is not None:

                create_audit_log(
                    request,
                    "LOGOUT",
                    (
                        f"Utilizador "
                        f"{request.user.username} "
                        f"terminou a sessão."
                    ),
                    status_code=200,
                    result="SUCCESS",
                )

            return Response(
                {
                    "message": "Logout successful.",
                    "detail": "Logout successful.",
                },
                status=status.HTTP_200_OK,
            )

        except TokenError:

            return Response(
                {
                    "detail": (
                        "Invalid, expired or "
                        "blacklisted refresh token."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        except (
            ValueError,
            TypeError,
        ):

            return Response(
                {
                    "detail": (
                        "Invalid refresh token."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
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

        # ======================================================
        # MFA MUST BE ENABLED
        # ======================================================

        if not user.mfa_enabled:

            return Response(
                {
                    "error": (
                        "MFA must be enabled before "
                        "generating recovery codes."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ======================================================
        # CHECK IF THIS IS A REGENERATION
        # ======================================================

        has_existing_codes = (
            MFARecoveryCode.objects
            .filter(user=user)
            .exists()
        )

        # ======================================================
        # STRONG REAUTHENTICATION FOR REGENERATION
        # ======================================================

        if has_existing_codes:

            password = request.data.get(
                "password"
            )

            code = request.data.get(
                "code"
            )

            # --------------------------------------------------
            # PASSWORD REQUIRED
            # --------------------------------------------------

            if not password:

                create_audit_log(
                    request,
                    "MFA_RECOVERY_REAUTH_FAILED",
                    (
                        "Regeneração de recovery codes "
                        "recusada: password ausente."
                    ),
                    status_code=400,
                    result="FAILURE",
                )

                return Response(
                    {
                        "password": (
                            "Current password is required "
                            "to regenerate recovery codes."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # --------------------------------------------------
            # TOTP REQUIRED
            # --------------------------------------------------

            if not code:

                create_audit_log(
                    request,
                    "MFA_RECOVERY_REAUTH_FAILED",
                    (
                        "Regeneração de recovery codes "
                        "recusada: código MFA ausente."
                    ),
                    status_code=400,
                    result="FAILURE",
                )

                return Response(
                    {
                        "code": (
                            "MFA code is required to "
                            "regenerate recovery codes."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # --------------------------------------------------
            # USER LOCK
            # --------------------------------------------------

            with transaction.atomic():

                locked_user = (
                    User.objects
                    .select_for_update()
                    .get(pk=user.pk)
                )

                # ----------------------------------------------
                # PASSWORD VALIDATION
                # ----------------------------------------------

                if not locked_user.check_password(
                    password
                ):

                    create_audit_log(
                        request,
                        "MFA_RECOVERY_REAUTH_FAILED",
                        (
                            "Regeneração de recovery codes "
                            "recusada: password inválida."
                        ),
                        status_code=400,
                        result="FAILURE",
                    )

                    return Response(
                        {
                            "password": (
                                "Invalid current password."
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # ----------------------------------------------
                # MFA SECRET CHECK
                # ----------------------------------------------

                if not locked_user.mfa_secret:

                    create_audit_log(
                        request,
                        "MFA_RECOVERY_REAUTH_FAILED",
                        (
                            "Regeneração de recovery codes "
                            "recusada: MFA sem secret."
                        ),
                        status_code=400,
                        result="FAILURE",
                    )

                    return Response(
                        {
                            "code": (
                                "MFA configuration is invalid."
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # ----------------------------------------------
                # TOTP VALIDATION
                # ----------------------------------------------

                counter = (
                    verify_totp_code_with_counter(
                        locked_user.mfa_secret,
                        code,
                    )
                )

                if counter is None:

                    create_audit_log(
                        request,
                        "MFA_RECOVERY_REAUTH_FAILED",
                        (
                            "Regeneração de recovery codes "
                            "recusada: código MFA inválido."
                        ),
                        status_code=400,
                        result="FAILURE",
                    )

                    return Response(
                        {
                            "code": (
                                "Invalid MFA code."
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # ----------------------------------------------
                # TOTP ANTI-REPLAY
                # ----------------------------------------------

                if (
                    locked_user.mfa_last_used_counter
                    is not None
                    and
                    counter
                    <=
                    locked_user.mfa_last_used_counter
                ):

                    create_audit_log(
                        request,
                        "MFA_RECOVERY_REAUTH_FAILED",
                        (
                            "Regeneração de recovery codes "
                            "recusada: código MFA reutilizado."
                        ),
                        status_code=400,
                        result="FAILURE",
                    )

                    return Response(
                        {
                            "code": (
                                "MFA code has already "
                                "been used."
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # ----------------------------------------------
                # CONSUME TOTP COUNTER
                # ----------------------------------------------

                locked_user.mfa_last_used_counter = (
                    counter
                )

                locked_user.save(
                    update_fields=[
                        "mfa_last_used_counter"
                    ]
                )

            # ==================================================
            # REAUTH SUCCESS
            # ==================================================

            create_audit_log(
                request,
                "MFA_RECOVERY_REAUTH_SUCCESS",
                (
                    "Reautenticação forte concluída "
                    "para regeneração de recovery codes."
                ),
                status_code=200,
                result="SUCCESS",
            )

        # ======================================================
        # GENERATE / REGENERATE
        # ======================================================

        codes = generate_recovery_codes(
            user
        )

        action = (
            "MFA_RECOVERY_CODES_REGENERATED"
            if has_existing_codes
            else
            "MFA_RECOVERY_CODES_GENERATED"
        )

        description = (
            f"Recovery codes regenerados para "
            f"{user.username}"
            if has_existing_codes
            else
            f"Recovery codes gerados para "
            f"{user.username}"
        )

        create_audit_log(
            request,
            action,
            description,
            status_code=200,
            result="SUCCESS",
        )

        return Response(
            {
                "message": (
                    "Recovery codes regenerated successfully."
                    if has_existing_codes
                    else
                    "Recovery codes generated successfully."
                ),
                "recovery_codes": codes,
            },
            status=status.HTTP_200_OK,
        )

class UserSessionListView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        sessions = (
            UserSession.objects
            .filter(user=request.user)
            .order_by("-last_activity")
        )

        data = []

        for session in sessions:

            data.append(
                {
                    "id": str(session.id),
                    "device_name": session.device_name,
                    "ip_address": session.ip_address,
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                    "expires_at": session.expires_at,
                    "revoked": session.is_revoked,
                }
            )

        return Response(
            data,
            status=status.HTTP_200_OK,
        )



class UserSessionRevokeView(APIView):

    permission_classes = [IsAuthenticated]

    def delete(self, request, session_id):

        try:
            session = UserSession.objects.get(
                id=session_id,
                user=request.user,
            )

        except UserSession.DoesNotExist:
            raise NotFound(
                "Session not found."
            )

        if session.revoked_at is None:

            blacklist_user_session(
                session
            )

            session.revoked_at = timezone.now()

            session.save(
                update_fields=[
                    "revoked_at",
                ]
            )

        return Response(
            {
                "detail": (
                    "Session revoked successfully."
                )
            },
            status=status.HTTP_200_OK,
        )


class UserSessionRevokeAllView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        keep_current = request.data.get(
            "keep_current",
            True,
        )

        session_id = request.auth.get(
            "session_id"
        )

        sessions = UserSession.objects.filter(
            user=request.user,
            revoked_at__isnull=True,
        )

        if (
            keep_current
            and session_id
        ):
            sessions = sessions.exclude(
                id=session_id
            )

        now = timezone.now()

        revoked_count = 0

        for session in sessions:

            blacklist_user_session(
                session
            )

            session.revoked_at = now

            session.save(
                update_fields=[
                    "revoked_at",
                ]
            )

            revoked_count += 1

        return Response(
            {
                "detail": (
                    "Sessions revoked successfully."
                ),
                "revoked_count": revoked_count,
                "kept_current": bool(
                    keep_current
                    and session_id
                ),
            },
            status=status.HTTP_200_OK,
        )