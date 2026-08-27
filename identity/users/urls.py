from django.urls import path

from .views import (
    UserList,
    UserDetail,
    CurrentUserView,
    ChangePasswordView,
    LogoutView,
    AuditLogView,
    RoleListView,
    RoleDetailView,
    PermissionListView,
    PermissionDetailView,
    ActivateUserView,
    DeactivateUserView,
    GroupListView,
    GroupDetailView,
    MFASetupView,
    MFAVerifyView,
)


urlpatterns = [

    # ========================================================
    # USERS
    # ========================================================

    path(
        "",
        UserList.as_view(),
        name="user-list"
    ),

    path(
        "me/",
        CurrentUserView.as_view(),
        name="current-user"
    ),

    path(
        "me/mfa/setup/",
        MFASetupView.as_view(),
        name="mfa-setup"
    ),

    path(
        "me/mfa/verify/",
        MFAVerifyView.as_view(),
        name="mfa-verify"
    ),

    path(
        "change-password/",
        ChangePasswordView.as_view(),
        name="change-password"
    ),

    path(
        "logout/",
        LogoutView.as_view(),
        name="logout"
    ),

    path(
        "<int:id>/",
        UserDetail.as_view(),
        name="user-detail"
    ),

    # ========================================================
    # ACTIVATE / DEACTIVATE USER
    # ========================================================

    path(
        "<int:id>/activate/",
        ActivateUserView.as_view(),
        name="activate-user"
    ),

    path(
        "<int:id>/deactivate/",
        DeactivateUserView.as_view(),
        name="deactivate-user"
    ),

    # ========================================================
    # AUDIT
    # ========================================================

    path(
        "audit/",
        AuditLogView.as_view(),
        name="audit"
    ),

    # ========================================================
    # ROLES
    # ========================================================

    path(
        "roles/",
        RoleListView.as_view(),
        name="role-list"
    ),

    path(
        "roles/<int:id>/",
        RoleDetailView.as_view(),
        name="role-detail"
    ),

    # ========================================================
    # PERMISSIONS
    # ========================================================

    path(
        "permissions/",
        PermissionListView.as_view(),
        name="permission-list"
    ),

    path(
        "permissions/<int:id>/",
        PermissionDetailView.as_view(),
        name="permission-detail"
    ),

path(
    "groups/",
    GroupListView.as_view(),
    name="group-list"
),

path(
    "groups/<int:id>/",
    GroupDetailView.as_view(),
    name="group-detail"
),
]