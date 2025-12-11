# POS Inventory Django Project

This is a minimal Django project configured as a multi-store Inventory + POS system.

Quick start (PythonAnywhere-compatible):

1. Upload this project to your PythonAnywhere account (via Git or upload the zip).
2. Create and activate a virtualenv with Python 3.11 (or 3.10).
3. Install requirements:
   pip install -r requirements.txt
4. Set environment variable DJANGO_SETTINGS_MODULE=pos_project.settings (not necessary if running manage.py)
5. Update SECRET_KEY and DEBUG in pos_project/settings.py for production.
6. Run migrations:
   python manage.py migrate
7. Create superuser:
   python manage.py createsuperuser
8. Collect static:
   python manage.py collectstatic
9. Run server (for testing):
   python manage.py runserver

Notes for PythonAnywhere:
- Use the web tab to configure WSGI and static files.
- For printing receipts, use browser `window.print()` on the till workstation.
