import json
import uuid
import csv, io
from decimal import Decimal
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.http import require_POST, require_GET, require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.db import transaction, IntegrityError, models
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from .models import Product, InventoryItem, Store, Sale, SaleItem, StaffProfile, StockTake, StockTakeItem, InventoryAdjustment, PriceChange, PAYMENT_CASH, PAYMENT_CARD, PAYMENT_MOBILE
from .forms import ProductForm, ProductCreateForm, InventoryEditForm, BulkUploadForm
from django.urls import reverse
from django.utils.text import slugify
from inventory.models import Store
from inventory.models import StaffProfile
from .models import Store, Sale
from django.db.models import Q





def owner_or_manager_required(view_func):
    def _wrapped(request, *args, **kwargs):
        profile = getattr(request.user, 'profile', None)
        if not profile or not (profile.is_owner or profile.is_manager):
            return HttpResponseForbidden("Not allowed")
        return view_func(request, *args, **kwargs)
    return _wrapped

def _json_error(msg, status=400):
    return JsonResponse({'error': msg}, status=status)

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("dashboard")  
        else:
            return render(request, "inventory/login.html", {
                "error": "Invalid username or password"
            })

    return render(request, "inventory/login.html")



@login_required
def home(request):
    profile = getattr(request.user, 'profile', None)

    # Determine role
    role = profile.role if profile else None

    # Determine visible stores
    if role == 'owner':
        stores = Store.objects.all()
    elif role == 'manager':
        stores = profile.stores.all()
    else:  # cashier
        stores = profile.stores.all()

    # Sales for those stores
    sales = Sale.objects.filter(store__in=stores)

    total_earnings = sales.aggregate(total=models.Sum('total'))['total'] or 0
    total_earnings = float(total_earnings)

    # User count only for owners
    user_count = User.objects.count() if role == 'owner' else None

    # Group earnings per store
    store_earnings = (
        sales.values('store__id', 'store__name')
        .annotate(earnings=models.Sum('total'))
        .order_by('store__name')
    )

    
    if role == 'owner':
        store_count = stores.count()
        avg_per_store = total_earnings / store_count if store_count > 0 else 0
    else:
        avg_per_store = None

    context = {
        'stores': stores,
        'total_earnings': total_earnings,
        'user_count': user_count,
        'store_earnings': store_earnings,
        'role': role,
        'avg_per_store': avg_per_store,  
    }

    return render(request, 'inventory/home.html', context)



from django.http import HttpResponseForbidden

@login_required
def product_list(request, store_id):

    profile = request.user.profile

    if profile.is_cashier:
        return HttpResponseForbidden("You do not have permission to view products.")

    if not (profile.is_owner or profile.is_manager):
        return HttpResponseForbidden("You do not have permission to view products.")

    store = get_object_or_404(profile.stores, id=store_id)

    q = request.GET.get('q', '').strip()

    items = InventoryItem.objects.filter(store=store).select_related('product').order_by('product__name')

    if q:
        items = items.filter(
            models.Q(product__name__icontains=q) |
            models.Q(product__sku__icontains=q) |
            models.Q(product__barcode__icontains=q)
        )

    return render(request, 'inventory/product_list.html', {
        'store': store,
        'inventory': items,
        'q': q,
    })


# Product create view
@login_required
@owner_or_manager_required
def product_create(request, store_id):
    store = get_object_or_404(Store, id=store_id)
    profile = getattr(request.user, 'profile', None)
    if request.method == 'POST':
        form = ProductCreateForm(request.POST)
        if form.is_valid():
            product = form.save(commit=False)
            product.save()

            store_ids = form.cleaned_data.get('store_choices')
            price = form.cleaned_data.get('price') or 0
            quantity = form.cleaned_data.get('quantity') or 0

            if profile and profile.is_owner and store_ids:
                targets = store_ids
            else:
                targets = [store]

            for s in targets:
                inv, created = InventoryItem.objects.get_or_create(store=s, product=product, defaults={'price': price, 'quantity': quantity})
                if not created:
                    inv.price = price or inv.price
                    inv.quantity = quantity or inv.quantity
                    inv.save()

            messages.success(request, 'Product created and inventory initialized.')
            return redirect('inventory:product_list', store_id=store.id)
        else:
            messages.error(request, 'Please fix the errors below.')
    else:
        form = ProductCreateForm()
        if profile and profile.is_manager and not profile.is_owner:
            form.fields['store_choices'].queryset = profile.stores.all()

    return render(request, 'inventory/product_create.html', {'form': form, 'store': store})

@login_required
@owner_or_manager_required
def product_edit(request, store_id, product_id):
    store = get_object_or_404(Store, id=store_id)
    product = get_object_or_404(Product, id=product_id)
    inventory = InventoryItem.objects.filter(store=store, product=product).first()
    if not inventory:
        messages.error(request, 'This product is not present in this store inventory.')
        return redirect('inventory:product_list', store_id=store.id)

    if request.method == 'POST':
        pform = ProductForm(request.POST, instance=product)
        iform = InventoryEditForm(request.POST)
        if pform.is_valid() and iform.is_valid():
            pform.save()
            inventory.price = iform.cleaned_data['price']
            inventory.quantity = iform.cleaned_data['quantity']
            inventory.save()
            messages.success(request, 'Product and inventory updated.')
            return redirect('inventory:product_list', store_id=store.id)
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        pform = ProductForm(instance=product)
        iform = InventoryEditForm(initial={'price': inventory.price, 'quantity': inventory.quantity})

    return render(request, 'inventory/product_edit.html', {
        'store': store, 'product': product, 'pform': pform, 'iform': iform
    })
@login_required
@owner_or_manager_required
def product_delete(request, store_id, product_id):
    store = get_object_or_404(Store, id=store_id)
    product = get_object_or_404(Product, id=product_id)

    inventory = InventoryItem.objects.filter(store=store, product=product).first()
    if not inventory:
        messages.error(request, "Product does not exist in this store.")
        return redirect('inventory:product_list', store_id=store.id)

    if request.method == "POST":
        inventory.delete()
        messages.success(request, "Product removed from this store.")
        return redirect('inventory:product_list', store_id=store.id)

    return render(request, "inventory/product_delete_confirm.html", {
        "store": store,
        "product": product
    })


@login_required
def store_list(request):
    profile = request.user.profile

    if not profile.is_owner:
        return redirect('inventory:home')

    stores = Store.objects.all()
    return render(request, 'inventory/store_list.html', {'stores': stores})


@login_required
def store_add(request):
    profile = request.user.profile

    if not profile.is_owner:
        return redirect('inventory:home')

    if request.method == "POST":
        name = request.POST.get("name")

        if name:
            Store.objects.create(name=name)
            messages.success(request, "Store added successfully!")
            return redirect('inventory:store_list')

    return render(request, 'inventory/store_add.html')


@login_required
def store_edit(request, store_id):
    profile = request.user.profile

    if not profile.is_owner:
        return redirect('inventory:home')

    store = get_object_or_404(Store, id=store_id)

    if request.method == "POST":
        name = request.POST.get("name")

        if name:
            store.name = name
            store.save()
            messages.success(request, "Store updated successfully!")
            return redirect('inventory:store_list')

    return render(request, 'inventory/store_edit.html', {'store': store})


@login_required
def store_delete(request, store_id):
    profile = request.user.profile

    if not profile.is_owner:
        return redirect('inventory:home')

    store = get_object_or_404(Store, id=store_id)
    store.delete()
    messages.success(request, "Store deleted successfully!")
    return redirect('inventory:store_list')



@login_required
def stock_take(request, store_id):
    store = get_object_or_404(Store, id=store_id)
    inventory = InventoryItem.objects.filter(store=store).select_related('product')
    if request.method == 'POST':
        stock = StockTake.objects.create(store=store, performed_by=request.user)
        for inv in inventory:
            key = f'count_{inv.id}'
            if key in request.POST:
                counted = int(request.POST[key])
                StockTakeItem.objects.create(stocktake=stock, product=inv.product, counted_quantity=counted, inventory_item=inv)
                if inv.quantity != counted:
                    InventoryAdjustment.objects.create(inventory_item=inv, previous_quantity=inv.quantity, new_quantity=counted, reason='Stock take', performed_by=request.user)
                    inv.quantity = counted
                    inv.save()
        return redirect('inventory:product_list', store_id=store.id)
    return render(request, 'inventory/stock_take.html', {'store': store, 'inventory': inventory})

@login_required
def users_page(request):
    stores = Store.objects.all()
    users = (
        User.objects.all()
        .select_related("profile")
        .prefetch_related("profile__stores")
    )

    return render(request, "inventory/users.html", {
        "stores": stores,
        "users": users,
    })



def users_create_page(request):
    stores = Store.objects.all()
    return render(request, "inventory/users_create.html", {"stores": stores})

@login_required
@require_http_methods(["GET", "POST"])
def price_update(request):
    """
    Owner-only bulk price update.

    Accepts multipart/form-data with a CSV file field named 'file'.
    CSV must contain either 'sku' or 'barcode' column and a 'price' column.
    Example rows:
      sku,price
      SKU-1A2B3C,9.50

    Returns JSON if AJAX (Content-Type application/json or Fetch), otherwise renders page with results.
    """
    profile = getattr(request.user, "profile", None)
    if not profile or not profile.is_owner:
        if request.headers.get("x-requested-with") == "XMLHttpRequest" or request.content_type == "application/json":
            return JsonResponse({"success": False, "message": "Not allowed"}, status=403)
        return HttpResponseForbidden("Not allowed")

    results = None
    if request.method == "POST":
        # Validate file
        csvfile = request.FILES.get("file")
        if not csvfile:
            if request.headers.get("x-requested-with") == "XMLHttpRequest":
                return JsonResponse({"success": False, "message": "No file uploaded"}, status=400)
            messages.error(request, "Please upload a CSV file.")
            return render(request, "inventory/price_update.html", {"results": []})

        decoded = csvfile.read().decode("utf-8-sig")  # handle BOM
        reader = csv.DictReader(io.StringIO(decoded))
        required_price = "price"
        # automatically detect sku vs barcode
        key_field = None
        if "sku" in reader.fieldnames:
            key_field = "sku"
        elif "barcode" in reader.fieldnames:
            key_field = "barcode"
        else:
            # invalid format
            if request.headers.get("x-requested-with"):
                return JsonResponse({"success": False, "message": "CSV must include 'sku' or 'barcode' column and 'price' column"}, status=400)
            messages.error(request, "CSV must include 'sku' or 'barcode' column and 'price' column")
            return render(request, "inventory/price_update.html", {"results": []})

        summary = {"updated": 0, "not_found": 0, "errors": []}
        audit_lines = []

        with transaction.atomic():
            for i, row in enumerate(reader, start=1):
                identifier = (row.get(key_field) or "").strip()
                price_raw = (row.get(required_price) or "").strip()
                if not identifier or not price_raw:
                    summary["errors"].append(f"Line {i}: missing {key_field} or price")
                    continue
                try:
                    new_price = Decimal(price_raw)
                except Exception:
                    summary["errors"].append(f"Line {i}: invalid price '{price_raw}'")
                    continue

                # find product
                product_qs = Product.objects.filter(**{key_field: identifier})
                product = product_qs.first()
                if not product:
                    summary["not_found"] += 1
                    summary["errors"].append(f"Line {i}: product not found ({key_field}={identifier})")
                    continue

                # update all inventory items for that product
                inv_qs = InventoryItem.objects.filter(product=product)
                if not inv_qs.exists():
                    summary["not_found"] += 1
                    summary["errors"].append(f"Line {i}: product has no inventory entries ({product.name})")
                    continue

                for inv in inv_qs.select_for_update():
                    prev = inv.price
                    if prev != new_price:
                        inv.price = new_price
                        inv.save()
                        PriceChange.objects.create(
                            inventory_item=inv,
                            previous_price=prev,
                            new_price=new_price,
                            changed_by=request.user
                        )
                        audit_lines.append(f"{product.sku} @ {inv.store.name}: {prev} → {new_price}")
                        summary["updated"] += 1
                # end inventory loop

        results = {
            "summary": summary,
            "audit_lines": audit_lines
        }

        # If AJAX/fetch, return JSON
        if request.headers.get("x-requested-with") == "XMLHttpRequest" or request.content_type == "application/json":
            return JsonResponse({"success": True, "results": results})

    # GET or fallback render
    return render(request, "inventory/price_update.html", {"results": results})

from django.db.models import Q

@login_required
def cashier_pos(request, store_id):
    if not request.user.profile.is_cashier:
        return HttpResponseForbidden("You do not have permission to access the POS Till.")

    


@login_required
@require_POST
def lookup_barcode(request):
    data = json.loads(request.body)
    query = data.get("barcode", "").strip()
    store_id = data.get("store_id")

    if not query:
        return JsonResponse({"error": "Empty search"}, status=400)

    try:
        store = Store.objects.get(id=store_id)
    except Store.DoesNotExist:
        return JsonResponse({"error": "Store not found"}, status=404)

    # Lookup using InventoryItem (not Product)
    item = InventoryItem.objects.select_related("product").filter(
        store=store,
        product__is_active=True
    ).filter(
        Q(product__barcode__icontains=query) |
        Q(product__name__icontains=query)
    ).first()

    if not item:
        return JsonResponse({"error": "Product not found"}, status=404)

    product = item.product

    return JsonResponse({
        "product_id": product.id,
        "name": product.name,
        "sku": product.barcode,
        "price": float(item.price)
    }
    )



@login_required
@require_POST
def create_sale(request):
    try:
        data = json.loads(request.body)
    except Exception:
        return _json_error('Invalid JSON')

    store_id = data.get('store_id')
    items = data.get('items', [])
    payment_method = data.get('payment_method', PAYMENT_CASH)
    payment_reference = data.get('payment_reference', '')

    if not store_id or not items:
        return _json_error('store_id and items required')

    store = get_object_or_404(Store, id=store_id)
    profile = getattr(request.user, 'profile', None)
    if profile and profile.is_cashier:
        if not profile.stores.filter(id=store.id).exists():
            return _json_error('Cashier not assigned to this store', status=403)

    if payment_method not in {PAYMENT_CASH, PAYMENT_CARD, PAYMENT_MOBILE}:
        return _json_error('Invalid payment method')

    with transaction.atomic():
        receipt_number = f"R-{timezone.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        sale = Sale.objects.create(
            store=store,
            cashier=request.user,
            payment_method=payment_method,
            payment_reference=payment_reference,
            receipt_number=receipt_number
        )
        total = Decimal('0.00')
        for it in items:
            pid = it.get('product_id')
            qty = int(it.get('quantity', 0) or 0)
            if qty <= 0:
                transaction.set_rollback(True)
                return _json_error('Invalid quantity')
            product = get_object_or_404(Product, id=pid)
            inv = InventoryItem.objects.select_for_update().filter(store=store, product=product).first()
            if not inv:
                transaction.set_rollback(True)
                return _json_error(f'Product {product.name} not in store inventory', status=404)
            if inv.quantity < qty:
                transaction.set_rollback(True)
                return _json_error(f'Insufficient quantity for {product.name}', status=409)
            unit_price = inv.price
            line_total = (unit_price * qty)
            SaleItem.objects.create(
                sale=sale,
                product=product,
                store=store,
                quantity=qty,
                unit_price=unit_price,
                line_total=line_total
            )
            previous_qty = inv.quantity
            inv.quantity = inv.quantity - qty
            inv.save()
            InventoryAdjustment.objects.create(
                inventory_item=inv,
                previous_quantity=previous_qty,
                new_quantity=inv.quantity,
                reason=f'Sale {sale.receipt_number}',
                performed_by=request.user
            )
            total += line_total
        sale.total = total
        sale.save()
    return JsonResponse({'sale_id': sale.id, 'receipt_url': f'/inventory/receipt/{sale.id}/', 'receipt_number': sale.receipt_number, 'total': str(sale.total)})

@login_required
@require_GET
def receipt_view(request, sale_id):
    sale = get_object_or_404(Sale, id=sale_id)
    profile = getattr(request.user, 'profile', None)
    if profile:
        if profile.is_cashier and sale.cashier != request.user:
            return HttpResponseForbidden('Not allowed')
        if profile.is_manager and not profile.stores.filter(id=sale.store.id).exists():
            return HttpResponseForbidden('Not allowed')
    return render(request, 'inventory/receipt.html', {'sale': sale, 'store': sale.store})

@login_required
@require_GET
def cashier_pos(request, store_id):
    store = get_object_or_404(Store, id=store_id)
    profile = getattr(request.user, 'profile', None)
    if profile:
        if profile.is_cashier and not profile.stores.filter(id=store.id).exists():
            return HttpResponseForbidden('Not allowed')
        if profile.is_manager and not profile.stores.filter(id=store.id).exists():
            return HttpResponseForbidden('Not allowed')
    return render(request, 'inventory/pos_till.html', {'store': store})

@login_required
@require_POST
def update_price_global(request):
    profile = getattr(request.user, 'profile', None)
    if not profile or not profile.is_owner:
        return _json_error('Only owner can update prices', status=403)
    try:
        data = json.loads(request.body)
    except Exception:
        return _json_error('Invalid JSON')
    product_id = data.get('product_id')
    new_price_str = data.get('new_price')
    scope = data.get('scope', 'all')
    if not product_id or new_price_str is None:
        return _json_error('product_id and new_price required')
    try:
        new_price = Decimal(new_price_str)
    except Exception:
        return _json_error('Invalid price format')
    from django.shortcuts import get_object_or_404
    product = get_object_or_404(Product, id=product_id)
    if scope == 'all':
        inv_qs = InventoryItem.objects.filter(product=product)
    elif isinstance(scope, dict) and 'store_ids' in scope:
        inv_qs = InventoryItem.objects.filter(product=product, store__id__in=scope['store_ids'])
    else:
        return _json_error('Invalid scope')
    changed = []
    with transaction.atomic():
        for inv in inv_qs.select_for_update():
            prev = inv.price
            inv.price = new_price
            inv.save()
            PriceChange.objects.create(inventory_item=inv, previous_price=prev, new_price=new_price, changed_by=request.user)
            changed.append({'store_id': inv.store.id, 'previous_price': str(prev), 'new_price': str(new_price)})
    return JsonResponse({'updated': changed})

@require_POST
def edit_user(request, user_id):
    if not request.user.profile.is_owner:
        return HttpResponseForbidden()

    user = User.objects.get(id=user_id)
    profile = user.profile

    # Get normal POST form fields
    username = request.POST.get("username")
    email = request.POST.get("email")
    role = request.POST.get("role")
    password = request.POST.get("password")
    stores = request.POST.getlist("stores")  # multiple select

    # Update fields
    user.username = username
    user.email = email
    profile.role = role

    if password:
        user.set_password(password)

    # Update stores
    profile.stores.clear()
    if stores:
        profile.stores.add(*stores)

    user.save()
    profile.save()

    return redirect("inventory:users")



@require_POST
def delete_user(request, user_id):
    if not request.user.profile.is_owner():
        return HttpResponseForbidden()

    try:
        user = User.objects.get(id=user_id)
        user.delete()
        return JsonResponse({"message": "User deleted successfully"})
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)


@login_required
@require_http_methods(["GET", "POST"])
def owner_create_user(request):
    # only owners allowed
    profile = getattr(request.user, "profile", None)
    if not profile or not profile.is_owner:
        # if AJAX/JSON request, return JSON; otherwise HTTP 403
        if request.content_type == "application/json":
            return JsonResponse({"success": False, "message": "Not allowed"}, status=403)
        return HttpResponseForbidden("Not allowed")

    # GET: return stores list (JSON) so frontend can populate store select
    if request.method == "GET":
        stores = list(Store.objects.all().values("id", "name"))
        return JsonResponse({"success": True, "stores": stores})

    # POST: handle creation (supports JSON and standard form posts)
    try:
        if request.content_type == "application/json":
            data = json.loads(request.body)
        else:
            data = request.POST

        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip()
        password = data.get("password") or "changeme123"
        role = data.get("role") or "cashier"

        # store_ids may come as JSON list or form list
        if request.content_type == "application/json":
            store_ids = data.get("store_ids", [])
        else:
            # form: send as multiple select (request.POST.getlist) or comma string
            if hasattr(data, "getlist"):
                store_ids = data.getlist("store_ids")
            else:
                store_ids = data.get("store_ids", [])

        # normalize store ids to ints
        if isinstance(store_ids, str):
            # allow comma separated in a pinch
            store_ids = [s.strip() for s in store_ids.split(",") if s.strip()]

        try:
            store_ids = [int(s) for s in store_ids]
        except Exception:
            store_ids = []

        if not username:
            return JsonResponse({"success": False, "message": "username required"}, status=400)

        # Prevent duplicate username early
        if User.objects.filter(username=username).exists():
            return JsonResponse({"success": False, "message": "Username already exists"}, status=400)

        with transaction.atomic():
            # create user
            user = User.objects.create_user(username=username, email=email, password=password)

            # create or get staff profile safely. Use get_or_create to avoid UNIQUE constraint
            sp, created_sp = StaffProfile.objects.get_or_create(user=user, defaults={"role": role})

            # if profile existed but role different, update role
            if not created_sp and sp.role != role:
                sp.role = role
                sp.save()

            # assign stores if any (Store queryset)
            if store_ids:
                stores_qs = Store.objects.filter(id__in=store_ids)
                sp.stores.set(stores_qs)

        # If request came from normal browser form, redirect to users listing
        if request.content_type != "application/json":
            messages.success(request, f"User {username} created")
            return redirect("inventory:users")

        # Return JSON success + minimal created user info
        return JsonResponse({
            "success": True,
            "message": "User created",
            "user": {"id": user.id, "username": user.username, "email": user.email},
            "profile": {"role": sp.role, "stores": [s.id for s in sp.stores.all()]}
        }, status=201)

    except IntegrityError as ie:
        # fallback: if something odd happened with a duplicate profile
        return JsonResponse({"success": False, "message": "Integrity error: " + str(ie)}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "message": str(e)}, status=500)


def owner_users(request):
    stores = Store.objects.all().values('id', 'name')
    users = User.objects.all().values('id', 'username', 'email', 'role')

    return render(request, "inventory/users.html", {
        "stores": list(stores),
        "users": list(users)
    })

@login_required
def owner_list_users(request):
    users = User.objects.all().select_related("profile")

    data = []
    for u in users:
        stores = []
        if hasattr(u, "profile"):
            stores = [s.name for s in u.profile.stores.all()]

        data.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.profile.role if hasattr(u, "profile") else "",
            "stores": stores,
        })

    return JsonResponse(data, safe=False)



def signup_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        # Check if username exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return render(request, "inventory/signup.html")

        # Check password match
        if password1 != password2:
            messages.error(request, "Passwords do not match")
            return render(request, "inventory/signup.html")

        # Create user with hashed password
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password1
        )

        messages.success(request, "Account created successfully. Please log in.")
        return redirect("login")

    return render(request, "inventory/signup.html")

def owner_or_manager_required(view_func):
    def _wrapped(request, *args, **kwargs):
        profile = getattr(request.user, 'profile', None)
        if not profile or not (profile.is_owner or profile.is_manager):
            return HttpResponseForbidden("Not allowed")
        return view_func(request, *args, **kwargs)
    return _wrapped

@login_required
@owner_or_manager_required
def bulk_upload(request, store_id):
    store = get_object_or_404(Store, id=store_id)
    if request.method == 'POST':
        form = BulkUploadForm(request.POST, request.FILES)
        if form.is_valid():
            csvfile = request.FILES['csv_file']
            data = csvfile.read().decode('utf-8')
            reader = csv.DictReader(io.StringIO(data))
            created = 0
            updated = 0
            errors = []
            # target stores chosen? owner can choose multiple; else use store
            target_stores = form.cleaned_data.get('stores') or [store]
            for i, row in enumerate(reader, start=1):
                name = row.get('name') or row.get('product') or row.get('title')
                barcode = row.get('barcode', '').strip()
                price = row.get('price', '') or 0
                qty = int(row.get('quantity') or 0)
                if not name:
                    errors.append(f'Row {i}: missing name')
                    continue
                product, pcreated = Product.objects.get_or_create(barcode=barcode, defaults={'name': name, 'description': row.get('description','')})
                if pcreated:
                    created += 1
                else:
                    updated += 1
                # create inventory for each target store
                for s in target_stores:
                    inv, icreated = InventoryItem.objects.get_or_create(store=s, product=product, defaults={'price': price, 'quantity': qty})
                    if not icreated:
                        # update price/quantity if provided
                        inv.price = price or inv.price
                        inv.quantity = qty or inv.quantity
                        inv.save()
            messages.success(request, f'Upload finished: products created {created}, updated {updated}.')
            if errors:
                messages.warning(request, 'Some rows had issues: ' + '; '.join(errors[:5]))
            return redirect('inventory:product_list', store_id=store.id)
    else:
        form = BulkUploadForm()
        # Restrict store choices for manager
        profile = getattr(request.user, 'profile', None)
        if profile and profile.is_manager and not profile.is_owner:
            form.fields['stores'].queryset = profile.stores.all()

    return render(request, 'inventory/bulk_upload.html', {'form': form, 'store': store})

@login_required
def barcode_print(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    return render(request, 'inventory/barcode_print.html', {'product': product})

def logout_view(request):
    logout(request)
    return redirect("login")