from django.contrib import admin
from .models import Store, Product, InventoryItem, Sale, SaleItem, StockTake, StockTakeItem, InventoryAdjustment, PriceChange, StaffProfile

@admin.register(Store)
class StoreAdmin(admin.ModelAdmin):
    list_display = ('name', 'code', 'address')

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'sku', 'barcode', 'is_active')

@admin.register(InventoryItem)
class InventoryItemAdmin(admin.ModelAdmin):
    list_display = ('product', 'store', 'quantity', 'price')

@admin.register(Sale)
class SaleAdmin(admin.ModelAdmin):
    list_display = ('receipt_number', 'store', 'cashier', 'total', 'created_at')
    readonly_fields = ('created_at', )

admin.site.register(SaleItem)
admin.site.register(StockTake)
admin.site.register(StockTakeItem)
admin.site.register(InventoryAdjustment)
admin.site.register(PriceChange)
admin.site.register(StaffProfile)
