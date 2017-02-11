from django.conf.urls import patterns, include, url
from django.contrib import admin
from api_handler_app import views
admin.autodiscover()


urlpatterns = [
   url(r'^admin/', include(admin.site.urls)),
   url(r'^get_initial_token/', views.get_initial_token),
   url(r'^login_2fa/', views.get_login_2fa),
   url(r'^login/', views.get_login_2fa),
   url(r'^valid_pwd/',views.get_valid_pwd),
   url(r'^valid_ans/',views.get_valid_ans),
   url(r'^account_info/',views.get_account_info),
   url(r'^default_login/',views.get_default_login),
   url(r'^normal_login/',views.get_normal_login),
   url(r'^login_mode/', views.get_login_mode),
   url(r'^login_by_pass/', views.get_login_by_pass),
   url(r'^load_retention_type/', views.get_load_retention_type),
   url(r'^check_crkt_price_range/', views.get_check_crkt_price_range),
   url(r'^validate_GTD/', views.get_validate_GTD),
   url(r'^validate_SLM_price/', views.get_validate_SLM_price),
   url(r'^place_order/', views.get_place_order),
   url(r'^order_book/', views.get_order_book),
   url(r'^modify_order/', views.get_modify_order),
   url(r'^cancel_order/', views.get_cancel_order),
   url(r'^order_history/', views.get_order_history),
   url(r'^trade_book/', views.get_trade_book),
   url(r'^position_book/', views.get_position_book),
   url(r'^holding/', views.get_holding),
   url(r'^limits/', views.get_limits),
   url(r'^user_profile/', views.get_user_profile),
   url(r'^account_info/', views.get_account_info),
   url(r'^open_orders/', views.get_open_orders),
   url(r'^bo_holdings/', views.get_bo_holdings),
   url(r'^bo_Ul_Trades/', views.get_bo_Ul_Trades),
   url(r'^check_transaction_password/', views.get_check_transaction_password),
   url(r'^logout/', views.get_logout),
  ]