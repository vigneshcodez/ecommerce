from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
    openapi.Info(
        title='ecommerce',
        default_version='v1',
        description='ecommerce documentation',
        terms_of_service='https://www.google.com/policies/terms/',
        contact=openapi.Contact(email='admin@gmail.com'),
        license=openapi.License(name='BSD Licence')
    ),
    public=True,
    permission_classes=(permissions.AllowAny,)
)
