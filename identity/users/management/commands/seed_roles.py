from django.core.management.base import BaseCommand

from users.models import Role, Permission


class Command(BaseCommand):

    help = "Cria papéis e permissões iniciais"


    def handle(self, *args, **kwargs):

        permissions = {

            "user.create": "Criar utilizadores",

            "user.update": "Atualizar utilizadores",

            "user.delete": "Eliminar utilizadores",

            "user.view": "Consultar utilizadores",

            "audit.view": "Consultar auditoria",

            "role.manage": "Gerir papéis",

            "password.change": "Alterar palavra-passe",

            "profile.update": "Atualizar perfil"

        }


        permission_objects = {}

        for code, description in permissions.items():

            permission, created = Permission.objects.get_or_create(

                code=code,

                defaults={

                    "description": description

                }

            )

            permission_objects[code] = permission


        admin, _ = Role.objects.get_or_create(

            name="ADMIN",

            defaults={

                "description": "Administrador"

            }

        )


        manager, _ = Role.objects.get_or_create(

            name="MANAGER",

            defaults={

                "description": "Gestor"

            }

        )


        user, _ = Role.objects.get_or_create(

            name="USER",

            defaults={

                "description": "Utilizador"

            }

        )


        admin.permissions.set(

            Permission.objects.all()

        )


        manager.permissions.set([

            permission_objects["user.create"],

            permission_objects["user.update"],

            permission_objects["user.view"],

            permission_objects["password.change"],

            permission_objects["profile.update"]

        ])


        user.permissions.set([

            permission_objects["password.change"],

            permission_objects["profile.update"]

        ])


        self.stdout.write(

            self.style.SUCCESS(

                "Roles e permissões criados com sucesso."

            )

        )