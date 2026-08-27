from django.core.management.base import BaseCommand
from users.models import User, Role


class Command(BaseCommand):

    help = "Migra roles antigas para ForeignKey Role"


    def handle(self, *args, **kwargs):

        for user in User.objects.all():

            try:

                role = Role.objects.get(
                    name=user.role
                )

                user.role_fk = role
                user.save()

                self.stdout.write(
                    f"{user.username}: {role.name}"
                )

            except Role.DoesNotExist:

                self.stdout.write(
                    f"Role não encontrada: {user.role}"
                )
