from rest_framework.permissions import BasePermission


class IsAuthenticatedUser(BasePermission):
    """
    Qualquer utilizador autenticado.
    """

    def has_permission(self, request, view):

        return request.user.is_authenticated


class IsOwnerOrAdmin(BasePermission):
    """
    Utilizador pode aceder aos seus dados
    ou administrador pode aceder a todos.
    """

    def has_object_permission(
        self,
        request,
        view,
        obj
    ):

        return (
            obj == request.user
            or request.user.role == "ADMIN"
        )