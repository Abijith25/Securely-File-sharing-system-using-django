from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home, name='home'),
    path('decrypt/<str:doc_id>/', views.decrypt_and_download, name='decrypt_and_download'),
    path('shared-with-me/', views.shared_with_me, name='shared_with_me'),
    path('shared-by-me/', views.shared_by_me, name='shared_by_me'),
    path('logout/', views.logout_view, name='logout'),

]