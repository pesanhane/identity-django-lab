from .models import AuditLog
from rest_framework.exceptions import PermissionDenied


def create_audit_log(
    request,
    action,
    description,
    object_type=None,
    object_id=None,
    status_code=None,
    result="SUCCESS"
):

    user = getattr(request, "user", None)

    if user is None or not user.is_authenticated:
        user = None

    organization = None

    if user is not None:
        organization = user.organization

    if organization is None:
        raise PermissionDenied(
            "Não é possível criar AuditLog sem organização."
        )

    AuditLog.objects.create(
        organization=organization,
        user=user,
        action=action,
        description=description,
        ip_address=request.META.get("REMOTE_ADDR"),
        http_method=request.method,
        endpoint=request.path,
        user_agent=request.META.get("HTTP_USER_AGENT"),
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        status_code=status_code,
        result=result
    )


def get_current_organization(request):

    user = request.user

    if not user.is_authenticated:
        return None

    return user.organization


def require_organization(request):

    organization = get_current_organization(request)

    if organization is None:
        raise PermissionDenied(
            "Utilizador não pertence a nenhuma organização."
        )

    return organization