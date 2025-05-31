from ..models import ActivationCode
from django.core.mail import send_mail
import random
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status

def generate_activation_code():
    return random.randint(100000, 999999)

def send_activation_code(user):
    try:
        ActivationCode.objects.filter(user=user).delete()
        code_generator = generate_activation_code()
        ActivationCode.objects.create(user=user,code=code_generator)
        
        msg = f"""
        Dear {user.username}
        We Send You Activation Code, your code is :{code_generator}
        code will expired after 30 minutes
        """
        email = user.email
        send_mail(
            "Activation Code",
            msg,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,)
        return True
    except:
        return False
