from django.conf.urls import patterns, include, url
from django.contrib import admin
from restapp import views
admin.autodiscover()
urlpatterns = [
	url(r'^admin/', include(admin.site.urls)),
	url(r'^get_initial_token/', views.get_initial_token),
	url(r'^login_2fa/', views.get_login_2fa),
	#url(r'^user/(?P<pk>[0-9]+)/$', views.UserDetail.as_view()),
	]