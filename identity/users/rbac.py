from rest_framework.permissions import BasePermission


class HasPermission(BasePermission):

    permission_code = None

    def has_permission(self, request, view):

        # 1. Utilizador autenticado
        if not request.user.is_authenticated:
            return False

        # 2. Utilizador deve pertencer a uma organização
        if request.user.organization is None:
            return False

        # 3. Deve existir um código de permissão
        if self.permission_code is None:
            return False

        # 4. Verificar permission através das roles
        #    pertencentes à organização do utilizador
        return request.user.roles.filter(
            organization=request.user.organization,
            permissions__code=self.permission_code
        ).exists()


class CanCreateUser(HasPermission):
    permission_code = "user.create"


class CanUpdateUser(HasPermission):
    permission_code = "user.update"


class CanDeleteUser(HasPermission):
    permission_code = "user.delete"


class CanViewUser(HasPermission):
    permission_code = "user.view"


class CanViewAudit(HasPermission):
    permission_code = "audit.view"


class CanManageRole(HasPermission):
    permission_code = "role.manage"


class CanChangePassword(HasPermission):
    permission_code = "password.change"


class DynamicPermission(BasePermission):

    def has_permission(self, request, view):

        # 1. Autenticação
        if not request.user.is_authenticated:
            return False

        # 2. Superuser tem acesso administrativo global
        if request.user.is_superuser:
            return True

        # 3. Organização obrigatória
        if request.user.organization is None:
            return False

        # 4. Permissão requerida pela view
        required_permission = getattr(
            view,
            "permission_required",
            None
        )

        if required_permission is None:
            return False

        # 5. Verificar permissão através das roles
        #    dentro da organização do utilizador
        return request.user.roles.filter(
            organization=request.user.organization,
            permissions__code=required_permission
        ).exists()