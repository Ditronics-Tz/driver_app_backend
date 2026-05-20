from django.apps import AppConfig


class ManagerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "manager"

    def ready(self):
        from django.db.utils import OperationalError, ProgrammingError
        try:
            from .services import ensure_default_roles
            ensure_default_roles()
        except (OperationalError, ProgrammingError):
            return
