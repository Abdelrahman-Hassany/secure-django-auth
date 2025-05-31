from django.dispatch import receiver
from django.db.models.signals import post_save
from django.conf import settings
from .models import Profile
from .utils.send_code import send_activation_code

@receiver(post_save, sender=settings.AUTH_USER_MODEL) 
def ActivationSender(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
        
        