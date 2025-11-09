# IP Tracking Configuration
IP_TRACKING = {
    'ENABLED': True,
    'LOG_REQUESTS': True,
    'GEOLOCATION_ENABLED': True,
    'ANOMALY_DETECTION_ENABLED': True,
    'AUTO_BLOCKING_ENABLED': True,
    
    # Thresholds
    'HIGH_VOLUME_THRESHOLD': 100,  # requests per hour
    'SENSITIVE_ACCESS_THRESHOLD': 10,  # accesses to sensitive paths per hour
    'AUTH_FAILURE_THRESHOLD': 5,  # authentication failures per hour
    'SCANNING_THRESHOLD': 0.5,  # 50% 404 rate
    
    # Retention policies
    'LOG_RETENTION_DAYS': 30,
    'SUSPICIOUS_IP_RETENTION_DAYS': 90,
    'GEOLOCATION_CACHE_DAYS': 30,
    
    # Privacy
    'ANONYMIZE_IPS': False,  # Set to True to hash IP addresses
    'RESPECT_DNT_HEADER': True,  # Respect Do Not Track header
}

# Middleware configuration
MIDDLEWARE = [
    # ... other middleware
    'ip_tracking.middleware.IPTrackingMiddleware',
    'ip_tracking.middleware.SecurityHeadersMiddleware',
]

# Installed apps
INSTALLED_APPS = [
    # ... other apps
    'ip_tracking',
]

# Cache configuration (Redis recommended)
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Celery Configuration
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'

# Rate limiting configuration
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_VIEW = 'ip_tracking.views.rate_limit_exceeded'

# Security headers
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'ip_tracking_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/var/log/django/ip_tracking.log',
        },
    },
    'loggers': {
        'ip_tracking': {
            'handlers': ['ip_tracking_file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
