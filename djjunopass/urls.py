from django.urls import path

from .views import login_view, logout_view, verify_view

urlpatterns = [
    path('login/', login_view, name="login"),
    path('verify/', verify_view, name="verify"),
    path('logout/', logout_view, name="logout"),
]

app_name = 'djjunopass'
