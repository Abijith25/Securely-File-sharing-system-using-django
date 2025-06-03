from django.urls import path
from . import views

urlpatterns = [
    path('', views.login, name='login'),
    #(path(address,view function,url name for reference))

    path('/home', views.home, name='home'),  
    # The homepage for file upload
]
