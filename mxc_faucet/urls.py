from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("claimed", views.claimed, name="claimed"),
    path("forbidden", views.forbidden, name="forbidden"),
    path("invalidcaptcha", views.invalidcaptcha, name="invalidcaptcha"),
]