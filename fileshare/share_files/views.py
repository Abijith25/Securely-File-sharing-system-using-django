from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.contrib.auth.hashers import check_password


def home(request):
    return render(request, 'home.html')
# Create your views here.
def user_login(request):
    error = None
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        password = request.POST.get('password')
        with connection.cursor() as cursor:
            cursor.execute("SELECT user_password FROM users WHERE user_id=%s", [user_id])
            row = cursor.fetchone()
        if row and password:
            # Set session or custom login logic here
            request.session['user_id'] = user_id
            return redirect('home')
        else:
            error = "Invalid user ID or password"
    return render(request, 'login.html', {'error': error})