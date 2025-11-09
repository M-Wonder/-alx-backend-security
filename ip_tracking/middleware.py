import time
from django.http import HttpResponseForbidden, JsonResponse
from django.core.cache import cache
from django.utils import timezone
from django.db import transaction
import requests
import logging

from .models import RequestLog, BlockedIP, IPGeolocationCache

logger = logging.getLogger(__name__)

class IPTrackingMiddleware:
    """
    Comprehensive IP tracking middleware that handles:
    - IP logging with geolocation
    - IP blacklisting
    - Basic rate limiting
    - Request metadata collection
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.sensitive_paths = ['/admin/', '/login/', '/api/auth/', '/register/']
        self.rate_limit_config = {
            'anonymous': {'requests': 5, 'window': 60},  # 5 requests per minute
            'sensitive': {'requests': 10, 'window': 300},  # 10 requests per 5 minutes
        }

    def __call__(self, request):
        start_time = time.time()
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from blacklisted IP: {ip_address}")
            return HttpResponseForbidden(
                "Your IP address has been blocked due to suspicious activity."
            )

        # Check rate limiting for sensitive paths
        if any(request.path.startswith(path) for path in self.sensitive_paths):
            if self.is_rate_limited(ip_address, 'sensitive'):
                logger.warning(f"Rate limit exceeded for IP: {ip_address} on path: {request.path}")
                return JsonResponse(
                    {'error': 'Rate limit exceeded. Please try again later.'},
                    status=429
                )

        # Process the request
        response = self.get_response(request)
        
        # Log the request after processing to get status code
        processing_time = time.time() - start_time
        self.log_request(request, ip_address, response.status_code, processing_time)
        
        return response

    def get_client_ip(self, request):
        """Extract client IP address, handling proxy headers"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def is_ip_blocked(self, ip_address):
        """Check if IP is in the blocklist"""
        # Check cache first for performance
        cache_key = f'blocked_ip_{ip_address}'
        is_blocked = cache.get(cache_key)
        
        if is_blocked is None:
            is_blocked = BlockedIP.objects.filter(
                ip_address=ip_address,
                is_active=True
            ).exists()
            # Cache for 5 minutes
            cache.set(cache_key, is_blocked, 300)
        
        return is_blocked

    def is_rate_limited(self, ip_address, limit_type='anonymous'):
        """Basic in-memory rate limiting (Redis recommended for production)"""
        config = self.rate_limit_config.get(limit_type, self.rate_limit_config['anonymous'])
        cache_key = f'rate_limit_{ip_address}_{limit_type}'
        
        current = cache.get(cache_key, 0)
        if current >= config['requests']:
            return True
        
        cache.set(cache_key, current + 1, config['window'])
        return False

    def get_geolocation(self, ip_address):
        """Get geolocation data with caching"""
        # Skip private IPs
        if ip_address.startswith(('10.', '172.', '192.168.', '127.')):
            return None, None
        
        # Check database cache first
        try:
            cached_geo = IPGeolocationCache.objects.filter(
                ip_address=ip_address,
                expires_at__gt=timezone.now()
            ).first()
            if cached_geo:
                return cached_geo.country, cached_geo.city
        except Exception as e:
            logger.warning(f"Error accessing geolocation cache: {e}")

        # Check memory cache
        cache_key = f'geo_{ip_address}'
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data.get('country'), cached_data.get('city')

        # Fetch from external API
        try:
            country, city = self.fetch_geolocation_data(ip_address)
            
            # Cache in memory for 24 hours
            cache.set(cache_key, {'country': country, 'city': city}, 86400)
            
            # Cache in database for persistence
            self.cache_geolocation_in_db(ip_address, country, city)
            
            return country, city
        except Exception as e:
            logger.error(f"Geolocation API error for {ip_address}: {e}")
            return None, None

    def fetch_geolocation_data(self, ip_address):
        """Fetch geolocation data from external API"""
        try:
            # Using ip-api.com (free tier)
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            data = response.json()
            
            if data.get('status') == 'success':
                return data.get('country'), data.get('city')
        except requests.RequestException as e:
            logger.warning(f"Geolocation API request failed: {e}")
        
        return None, None

    def cache_geolocation_in_db(self, ip_address, country, city):
        """Cache geolocation data in database"""
        try:
            with transaction.atomic():
                expires_at = timezone.now() + timezone.timedelta(days=30)
                IPGeolocationCache.objects.update_or_create(
                    ip_address=ip_address,
                    defaults={
                        'country': country,
                        'city': city,
                        'expires_at': expires_at
                    }
                )
        except Exception as e:
            logger.error(f"Error caching geolocation in DB: {e}")

    def log_request(self, request, ip_address, status_code, processing_time):
        """Log request details asynchronously or in batch"""
        try:
            country, city = self.get_geolocation(ip_address)
            
            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                method=request.method,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status_code=status_code,
                country=country,
                city=city
            )
            
            # Log slow requests
            if processing_time > 1.0:  # More than 1 second
                logger.warning(
                    f"Slow request detected: {request.path} "
                    f"from {ip_address} took {processing_time:.2f}s"
                )
                
        except Exception as e:
            logger.error(f"Error logging request: {e}")


class SecurityHeadersMiddleware:
    """Add security headers to responses"""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Privacy-focused headers
        response['Permissions-Policy'] = 'geolocation=(), microphone=()'
        
        return response
