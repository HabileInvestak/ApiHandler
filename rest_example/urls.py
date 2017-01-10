from django.conf.urls import patterns, include, url
from django.contrib import admin
from restapp import views
admin.autodiscover()


urlpatterns = [
   url(r'^admin/', include(admin.site.urls)),
   url(r'^get_initial_token/', views.get_initial_token),
   url(r'^login/', views.get_login_2fa),
   ]
