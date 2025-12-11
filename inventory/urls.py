from django.urls import path
from . import views

app_name = 'inventory'

urlpatterns = [
    path('', views.home, name='home'),

    # POS
    path('pos/<int:store_id>/', views.cashier_pos, name='cashier_pos'),

    # Products
    path('store/<int:store_id>/products/', views.product_list, name='product_list'),
    path('store/<int:store_id>/products/create/', views.product_create, name='product_create'),
    path('store/<int:store_id>/products/<int:product_id>/edit/', views.product_edit, name='product_edit'),
    path('store/<int:store_id>/products/<int:product_id>/delete/', views.product_delete, name='product_delete'),
    path('store/<int:store_id>/products/bulk-upload/', views.bulk_upload, name='bulk_upload'),

    # Stock Take
    path('store/<int:store_id>/stock-take/', views.stock_take, name='stock_take'),

    # Users
    path('users/', views.users_page, name='users'),
    path('users/create/', views.users_create_page, name='users_create_page'),
    path('owner/users/create/', views.owner_create_user, name='owner_create_user'),
   path('owner/users/edit/<int:user_id>/', views.edit_user, name='edit_user'),
    path('owner/users/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('owner/list-users/', views.owner_list_users, name='owner_list_users'),

    # API
    path('api/lookup_barcode/', views.lookup_barcode, name='lookup_barcode'),
    path('api/create_sale/', views.create_sale, name='create_sale'),
    path('api/update_price/', views.update_price_global, name='update_price_global'),

    # Utils
    path('receipt/<int:sale_id>/', views.receipt_view, name='receipt'),
    path('product/<int:product_id>/print/', views.barcode_print, name='barcode_print'),
    path('price-update/', views.price_update, name='price_update'),
    path('logout/', views.logout_view, name='logout'),

    #Stores
    path('stores/', views.store_list, name='store_list'),
    path('stores/add/', views.store_add, name='store_add'),
    path('stores/<int:store_id>/edit/', views.store_edit, name='store_edit'),
    path('stores/<int:store_id>/delete/', views.store_delete, name='store_delete'),

]



