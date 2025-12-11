from django.urls import path, include
from inventory.views import login_view
from django.contrib import admin
from django.shortcuts import redirect
from inventory.views import login_view
from inventory import views


def root_redirect(request):
    return redirect('login')

urlpatterns = [
    path('', root_redirect),
    path('admin/', admin.site.urls),
    path('login/', login_view, name='login'),
    path('inventory/', include('inventory.urls')),
    path("signup/", views.signup_view, name="signup"),
    path("dashboard/", views.home, name="dashboard"),
    
]
