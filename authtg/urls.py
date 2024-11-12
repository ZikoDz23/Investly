# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.redirect_root, name='root_redirect'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('import-wallet/', views.import_wallet, name='import_wallet'),  # Secure this later
    path('main-page/', views.main_page, name='main_page'),
    path('send/', views.select_asset, name='select_asset'),
    path('send/<str:asset_type>/', views.send_asset, name='send_asset'),
    path('receive/', views.select_network, name='select_network'),
    path('receive/<str:network>/', views.receive_address, name='receive_address'),
    path('asset/<str:name>/', views.asset_detail, name='asset_detail'),
    path('profile/', views.profile, name='profile')
]
