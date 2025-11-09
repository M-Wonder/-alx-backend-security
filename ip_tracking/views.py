from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit
from django.http import HttpResponse

@ratelimit(key='ip', rate='5/m', method='GET', block=True)
def public_view(request):
    return HttpResponse("This is a public view with rate limiting")

@ratelimit(key='user', rate='10/m', method='GET', block=True)
@login_required
def sensitive_view(request):
    return HttpResponse("This is a sensitive view for authenticated users")

@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    if request.method == 'POST':
        # Handle login logic
        return HttpResponse("Login processed")
    return render(request, 'login.html')
