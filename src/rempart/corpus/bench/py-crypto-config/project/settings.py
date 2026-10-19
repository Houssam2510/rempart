import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
# rempart-expect: CODE-DEBUG-ENABLED
DEBUG = True
ALLOWED_HOSTS = ["app.example.com"]
# rempart-expect: CODE-CORS-PERMISSIVE
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
