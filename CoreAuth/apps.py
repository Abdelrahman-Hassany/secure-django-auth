from django.apps import AppConfig


class CoreauthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'CoreAuth'

    def ready(self):
        import CoreAuth.signals