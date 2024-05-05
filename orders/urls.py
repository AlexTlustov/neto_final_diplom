from django.contrib import admin
from django.urls import path, include
from orders import settings
from backend.views import HomeView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

urlpatterns = [
    path(r'jet/', include('jet.urls', 'jet')),
    path(r'jet/dashboard/', include('jet.dashboard.urls', 'jet-dashboard')),
    path(r'admin/', admin.site.urls),
    path('', HomeView.as_view(), name='home'),
    path('api/v1/', include('backend.urls', namespace='backend')),
    path('api/v1/schema/', SpectacularAPIView.as_view(), name='spectacular-schema'),
    path('api/v1/docs/', SpectacularSwaggerView.as_view(url_name='spectacular-schema'), name='swagger-ui'),
    path('api/v1/redoc/', SpectacularRedocView.as_view(url_name='spectacular-schema'), name='redoc'),
    path('accounts/', include('allauth.urls')),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns += [path("__debug__/", include(debug_toolbar.urls)),]