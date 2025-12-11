from django import forms
from .models import Product, InventoryItem, Store
from django.contrib.auth.models import User

class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['barcode', 'name', 'description', 'is_active']
        widgets = {
            'barcode': forms.TextInput(attrs={'class': 'form-control'}),
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

class ProductCreateForm(ProductForm):
    # price & quantity used to create InventoryItem for the current/selected stores
    price = forms.DecimalField(max_digits=12, decimal_places=2, required=False, widget=forms.NumberInput(attrs={'class':'form-control'}))
    quantity = forms.IntegerField(min_value=0, required=False, widget=forms.NumberInput(attrs={'class':'form-control'}))
    # owner may choose multiple stores
    store_choices = forms.ModelMultipleChoiceField(queryset=Store.objects.all(), required=False, widget=forms.SelectMultiple(attrs={'class':'form-control'}))

    class Meta(ProductForm.Meta):
        fields = ['barcode', 'name', 'description', 'is_active', 'price', 'quantity', 'store_choices']

class InventoryEditForm(forms.Form):
    price = forms.DecimalField(max_digits=12, decimal_places=2, widget=forms.NumberInput(attrs={'class':'form-control'}))
    quantity = forms.IntegerField(min_value=0, widget=forms.NumberInput(attrs={'class':'form-control'}))

class BulkUploadForm(forms.Form):
    csv_file = forms.FileField(widget=forms.FileInput(attrs={'class':'form-control'}))
    # If owner: allow selecting target stores for upload (optional)
    stores = forms.ModelMultipleChoiceField(queryset=Store.objects.all(), required=False, widget=forms.SelectMultiple(attrs={'class':'form-control'}))
