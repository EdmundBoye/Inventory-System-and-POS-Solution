from django.db import models
from django.contrib.auth.models import User
from decimal import Decimal
import uuid

ROLE_CASHIER = 'cashier'
ROLE_MANAGER = 'manager'
ROLE_OWNER = 'owner'
ROLE_CHOICES = [
    (ROLE_CASHIER, 'Cashier'),
    (ROLE_MANAGER, 'Manager'),
    (ROLE_OWNER, 'Owner'),
]

PAYMENT_CASH = 'cash'
PAYMENT_CARD = 'card'
PAYMENT_MOBILE = 'mobile'
PAYMENT_CHOICES = [
    (PAYMENT_CASH, 'Cash'),
    (PAYMENT_CARD, 'Bank Card'),
    (PAYMENT_MOBILE, 'Mobile Money'),
]

class Store(models.Model):
    name = models.CharField(max_length=255)
    code = models.CharField(max_length=50, unique=True)
    address = models.TextField(blank=True)

    def __str__(self):
        return self.name

class Product(models.Model):
    sku = models.CharField(max_length=64, unique=True, editable=False)
    barcode = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.sku:
            self.sku = self.generate_sku()
        super().save(*args, **kwargs)

    @staticmethod
    def generate_sku():
        return "SKU-" + uuid.uuid4().hex[:8].upper()

    def __str__(self):
        return f"{self.name} ({self.sku})"

class InventoryItem(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='inventory')
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='inventory_items')
    quantity = models.IntegerField(default=0)
    price = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal('0.00'))
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('store', 'product')

    def __str__(self):
        return f"{self.product.name} @ {self.store.name} — {self.quantity}"

class Sale(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='sales')
    cashier = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    total = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    payment_method = models.CharField(max_length=20, choices=PAYMENT_CHOICES, default=PAYMENT_CASH)
    payment_reference = models.CharField(max_length=255, blank=True, null=True)
    receipt_number = models.CharField(max_length=64, unique=True)

    def __str__(self):
        return f"Sale {self.receipt_number} - {self.store.name} - {self.total}"

class SaleItem(models.Model):
    sale = models.ForeignKey(Sale, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    unit_price = models.DecimalField(max_digits=12, decimal_places=2)
    line_total = models.DecimalField(max_digits=14, decimal_places=2)

    def __str__(self):
        return f"{self.quantity} x {self.product.name}"

class StockTake(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    performed_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"StockTake {self.id} @ {self.store.name} - {self.performed_at.date()}"

class StockTakeItem(models.Model):
    stocktake = models.ForeignKey(StockTake, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    counted_quantity = models.IntegerField()
    inventory_item = models.ForeignKey(InventoryItem, on_delete=models.SET_NULL, null=True, blank=True)

class InventoryAdjustment(models.Model):
    inventory_item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE)
    previous_quantity = models.IntegerField()
    new_quantity = models.IntegerField()
    reason = models.CharField(max_length=255, blank=True)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    performed_at = models.DateTimeField(auto_now_add=True)

class PriceChange(models.Model):
    inventory_item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE)
    previous_price = models.DecimalField(max_digits=12, decimal_places=2)
    new_price = models.DecimalField(max_digits=12, decimal_places=2)
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    changed_at = models.DateTimeField(auto_now_add=True)

class StaffProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_CASHIER)
    stores = models.ManyToManyField(Store, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.role}"

    @property
    def is_owner(self):
        return self.role == ROLE_OWNER

    @property
    def is_manager(self):
        return self.role == ROLE_MANAGER

    @property
    def is_cashier(self):
        return self.role == ROLE_CASHIER
