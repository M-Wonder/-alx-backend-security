from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q, F
from django.db import transaction
from django.core.cache import cache
import logging

from .models import RequestLog, SuspiciousIP, BlockedIP, IPGeolocationCache

logger = logging.getLogger(__name__)

@shared_task
def detect_suspicious_activity():
    """
    Comprehensive anomaly detection task
    Runs hourly to detect various types of suspicious activity
    """
    logger.info("Starting suspicious activity detection")
    one_hour_ago = timezone.now() - timedelta(hours=1)
    twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
    
    try:
        # 1. Detect high request volume IPs
        detect_high_volume_ips(one_hour_ago)
        
        # 2. Detect sensitive path access patterns
        detect_sensitive_path_access(one_hour_ago)
        
        # 3. Detect multiple authentication failures
        detect_auth_failures(one_hour_ago)
        
        # 4. Detect scanning behavior (multiple 404s)
        detect_scanning_behavior(one_hour_ago)
        
        # 5. Auto-block consistently suspicious IPs
        auto_block_suspicious_ips(twenty_four_hours_ago)
        
        # 6. Clean up old geolocation cache
        cleanup_old_geolocation_cache()
        
        logger.info("Suspicious activity detection completed successfully")
        
    except Exception as e:
        logger.error(f"Error in suspicious activity detection: {e}")


def detect_high_volume_ips(time_threshold):
    """Detect IPs with unusually high request volume"""
    high_volume_ips = RequestLog.objects.filter(
        timestamp__gte=time_threshold
    ).values('ip_address').annotate(
        request_count=Count('id'),
        unique_paths=Count('path', distinct=True)
    ).filter(request_count__gt=100)  # More than 100 requests per hour
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        
        SuspiciousIP.objects.update_or_create(
            ip_address=ip_address,
            reason='high_requests',
            defaults={
                'request_count': ip_data['request_count'],
                'details': {
                    'unique_paths_accessed': ip_data['unique_paths'],
                    'threshold_exceeded': 100,
                    'actual_requests': ip_data['request_count']
                }
            }
        )
        
        logger.info(f"High volume detected from {ip_address}: {ip_data['request_count']} requests")


def detect_sensitive_path_access(time_threshold):
    """Detect suspicious access to sensitive paths"""
    sensitive_paths = ['/admin/', '/login/', '/api/auth/', '/register/', '/reset-password/']
    
    for path in sensitive_paths:
        sensitive_access = RequestLog.objects.filter(
            timestamp__gte=time_threshold,
            path__startswith=path
        ).values('ip_address').annotate(
            access_count=Count('id'),
            success_rate=Count('id', filter=Q(status_code__lt=400)) * 100.0 / Count('id')
        ).filter(access_count__gt=10)  # More than 10 accesses to sensitive path
        
        for ip_data in sensitive_access:
            ip_address = ip_data['ip_address']
            
            SuspiciousIP.objects.update_or_create(
                ip_address=ip_address,
                reason='sensitive_access',
                defaults={
                    'request_count': ip_data['access_count'],
                    'details': {
                        'sensitive_path': path,
                        'access_count': ip_data['access_count'],
                        'success_rate': ip_data['success_rate']
                    }
                }
            )


def detect_auth_failures(time_threshold):
    """Detect multiple authentication failures"""
    auth_failures = RequestLog.objects.filter(
        timestamp__gte=time_threshold,
        path__in=['/login/', '/api/auth/login/'],
        status_code=401
    ).values('ip_address').annotate(
        failure_count=Count('id')
    ).filter(failure_count__gt=5)  # More than 5 auth failures
    
    for ip_data in auth_failures:
        ip_address = ip_data['ip_address']
        
        SuspiciousIP.objects.update_or_create(
            ip_address=ip_address,
            reason='multiple_failures',
            defaults={
                'request_count': ip_data['failure_count'],
                'details': {
                    'failure_count': ip_data['failure_count'],
                    'threshold': 5
                }
            }
        )


def detect_scanning_behavior(time_threshold):
    """Detect potential scanning behavior (high 404 rate)"""
    scanning_ips = RequestLog.objects.filter(
        timestamp__gte=time_threshold
    ).values('ip_address').annotate(
        total_requests=Count('id'),
        not_found_requests=Count('id', filter=Q(status_code=404))
    ).filter(
        total_requests__gt=20,
        not_found_requests__gt=F('total_requests') * 0.5  # More than 50% 404s
    )
    
    for ip_data in scanning_ips:
        ip_address = ip_data['ip_address']
        not_found_rate = (ip_data['not_found_requests'] / ip_data['total_requests']) * 100
        
        SuspiciousIP.objects.update_or_create(
            ip_address=ip_address,
            reason='suspicious_pattern',
            defaults={
                'request_count': ip_data['total_requests'],
                'details': {
                    'total_requests': ip_data['total_requests'],
                    'not_found_requests': ip_data['not_found_requests'],
                    'not_found_rate': round(not_found_rate, 2)
                }
            }
        )


def auto_block_suspicious_ips(time_threshold):
    """Automatically block IPs with consistent suspicious activity"""
    consistently_suspicious = SuspiciousIP.objects.filter(
        detected_at__gte=time_threshold,
        is_blocked=False
    ).values('ip_address').annotate(
        detection_count=Count('id'),
        unique_reasons=Count('reason', distinct=True)
    ).filter(
        detection_count__gte=3,  # Detected 3+ times in 24 hours
        unique_reasons__gte=2    # For at least 2 different reasons
    )
    
    for ip_data in consistently_suspicious:
        ip_address = ip_data['ip_address']
        
        # Add to blocklist
        BlockedIP.objects.get_or_create(
            ip_address=ip_address,
            defaults={
                'reason': 'Automatically blocked due to consistent suspicious activity across multiple categories',
                'expires_at': timezone.now() + timedelta(days=7)  # Temporary block for 7 days
            }
        )
        
        # Mark as blocked in SuspiciousIP
        SuspiciousIP.objects.filter(ip_address=ip_address).update(is_blocked=True)
        
        # Clear cache
        cache.delete(f'blocked_ip_{ip_address}')
        
        logger.info(f"Auto-blocked IP {ip_address} for consistent suspicious activity")


def cleanup_old_geolocation_cache():
    """Clean up expired geolocation cache entries"""
    expired_count = IPGeolocationCache.objects.filter(
        expires_at__lt=timezone.now()
    ).delete()[0]
    
    if expired_count > 0:
        logger.info(f"Cleaned up {expired_count} expired geolocation cache entries")


@shared_task
def cleanup_old_data():
    """
    Comprehensive data cleanup task
    Runs daily to maintain privacy and performance
    """
    logger.info("Starting data cleanup")
    
    # Clean up old request logs (keep only 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    deleted_logs_count = RequestLog.objects.filter(
        timestamp__lt=thirty_days_ago
    ).delete()[0]
    
    # Clean up old suspicious IP records (keep only 90 days)
    ninety_days_ago = timezone.now() - timedelta(days=90)
    deleted_suspicious_count = SuspiciousIP.objects.filter(
        detected_at__lt=ninety_days_ago
    ).delete()[0]
    
    # Clean up expired blocked IPs
    expired_blocks_count = BlockedIP.objects.filter(
        expires_at__lt=timezone.now(),
        is_active=True
    ).update(is_active=False)
    
    logger.info(
        f"Data cleanup completed: "
        f"{deleted_logs_count} logs, "
        f"{deleted_suspicious_count} suspicious IPs, "
        f"{expired_blocks_count} expired blocks removed"
    )


@shared_task
def generate_security_report():
    """
    Generate daily security report
    """
    twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
    
    report_data = {
        'total_requests': RequestLog.objects.filter(
            timestamp__gte=twenty_four_hours_ago
        ).count(),
        'blocked_requests': BlockedIP.objects.filter(
            created_at__gte=twenty_four_hours_ago
        ).count(),
        'suspicious_ips_detected': SuspiciousIP.objects.filter(
            detected_at__gte=twenty_four_hours_ago
        ).count(),
        'top_countries': list(
            RequestLog.objects.filter(
                timestamp__gte=twenty_four_hours_ago,
                country__isnull=False
            ).values('country').annotate(
                count=Count('id')
            ).order_by('-count')[:10]
        ),
        'frequent_attackers': list(
            SuspiciousIP.objects.filter(
                detected_at__gte=twenty_four_hours_ago
            ).values('ip_address', 'reason').annotate(
                count=Count('id')
            ).order_by('-count')[:10]
        )
    }
    
    # In a real implementation, you might:
    # - Send email to administrators
    # - Store in database
    # - Send to monitoring system
    
    logger.info(f"Security report generated: {report_data}")
    return report_data
