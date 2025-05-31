from django.shortcuts import render

def homepage(request):
    return render(request,'homepage.html')

def register(request):
    return render(request,'register.html')

def request_reset_password(request):
    return render(request,'request_reset_password.html')

def reset_password(request,token):
    return render(request,'reset_password.html',{'token': token})

def activation_page(request):
    return render(request,'activation_page.html')