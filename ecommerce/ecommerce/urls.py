from django.contrib import admin
from django.urls import path,include,re_path
from  django.conf import settings
from django.conf.urls.static import static
from .swagger import schema_view
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/',include('app.urls')),
    path('swagger/',schema_view.with_ui('swagger',cache_timeout=0),name='schema-swagger-ui'),
    path('redoc/',schema_view.with_ui('redoc',cache_timeout=0),name='schema-redoc'),
    path('',TemplateView.as_view(template_name='index.html')),
    # re_path(r'^.*$',TemplateView.as_view(template_name='index.html'))
] + static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)


    # re_path(r'^.*',TemplateView.as_view(template_name='index.html'))
