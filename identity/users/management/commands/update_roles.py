from django.core.management.base import BaseCommand
from users.models import User, Role


class Command(BaseCommand):

    def handle(self, *args, **kwargs):

        admin_role = Role.objects.get(name="ADMIN")
        user_role = Role.objects.get(name="USER")

        User.objects.filter(
            username="admin"
        ).update(
            role=admin_role
        )

        User.objects.exclude(
            username="admin"
        ).update(
            role=user_role
        )

        self.stdout.write(
            self.style.SUCCESS(
                "Roles atualizados"
            )
        )
