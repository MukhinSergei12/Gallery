from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='home'),
    path('google/login/', views.google_login, name='google-login'),
    path('google/callback/', views.google_callback, name='google-callback'),
    path('logout/', views.logout, name='logout'),
    path('gallery/', views.gallery, name='gallery'),
    path('upload/', views.upload, name='upload'),
]
