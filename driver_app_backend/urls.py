"""
URL configuration for driver_app_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse

def api_root(request):
    """API root endpoint"""
    return JsonResponse({
        'message': 'Welcome to Driver App API',
        'version': '1.0',
        'endpoints': {
            'auth': '/api/v1/auth/',
            'routing': '/api/v1/routing/',
            'data': '/api/v1/data/',
            'admin_api': '/api/admin/v1/',
            'admin': '/admin/',
            'oauth': '/api/v1/auth/oauth/',
        },
        'status': 'operational'
    })

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # API root
    path('', api_root, name='api_root'),
    path('api/', api_root, name='api_root_v2'),
    
    # API v1
    path('api/v1/auth/', include('authentication.urls')),
    path('api/v1/routing/', include('routing.urls')),
    path('api/v1/data/', include('data.urls')),
    path('api/admin/v1/', include('manager.urls')),
    
    # OAuth2 (alternative path)
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),

    
]
