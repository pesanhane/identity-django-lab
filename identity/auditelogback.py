class AuditLog(models.Model):

    ACTIONS = (
        ("LOGIN", "Login"),
        ("LOGIN_FAILURE", "Login Failure"),
        ("LOGOUT", "Logout"),

        ("TOKEN_INVALID", "Invalid Token"),
        ("ACCESS_DENIED", "Access Denied"),
        ("PRIVILEGE_ESCALATION_ATTEMPT", "Privilege Escalation Attempt"),

        ("CREATE_USER", "Create User"),
        ("UPDATE_USER", "Update User"),
        ("DELETE_USER", "Delete User"),

        ("ACTIVATE_USER", "Activate User"),
        ("DEACTIVATE_USER", "Deactivate User"),

        ("CHANGE_PASSWORD", "Change Password"),

        ("CREATE_ROLE", "Create Role"),
        ("UPDATE_ROLE", "Update Role"),
        ("DELETE_ROLE", "Delete Role"),

        ("CREATE_PERMISSION", "Create Permission"),
        ("UPDATE_PERMISSION", "Update Permission"),
        ("DELETE_PERMISSION", "Delete Permission"),
    )

    RESULTS = (
        ("SUCCESS", "Success"),
        ("FAILURE", "Failure"),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs"
    )

    action = models.CharField(
        max_length=50,
        choices=ACTIONS
    )

    description = models.TextField(
        blank=True
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    http_method = models.CharField(
        max_length=10,
        null=True,
        blank=True
    )

    endpoint = models.CharField(
        max_length=255,
        null=True,
        blank=True
    )

    user_agent = models.TextField(
        null=True,
        blank=True
    )

    object_type = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )

    object_id = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )

    status_code = models.PositiveIntegerField(
        null=True,
        blank=True
    )

    result = models.CharField(
        max_length=20,
        choices=RESULTS,
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.user} - {self.action}"