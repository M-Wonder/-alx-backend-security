from django.db import models

class RequestLog(models.Model):
    """Model to store all incoming request logs with geolocation data"""
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    method = models.CharField(max_length=10, default='GET')
    status_code = models.IntegerField(blank=True, null=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
            models.Index(fields=['country']),
            models.Index(fields=['method']),
            models.Index(fields=['status_code']),
        ]
        ordering = ['-timestamp']
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"

    def __str__(self):
        return f"{self.ip_address} - {self.method} {self.path} - {self.timestamp}"


class BlockedIP(models.Model):
    """Model to store blocked IP addresses"""
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"

    def __str__(self):
        return f"{self.ip_address} - {self.reason}"


class SuspiciousIP(models.Model):
    """Model to track suspicious IP addresses detected by anomaly detection"""
    REASON_CHOICES = [
        ('high_requests', 'High number of requests'),
        ('sensitive_access', 'Access to sensitive paths'),
        ('multiple_failures', 'Multiple authentication failures'),
        ('rate_limit_exceeded', 'Rate limit exceeded'),
        ('suspicious_pattern', 'Suspicious behavior pattern'),
    ]
    
    ip_address = models.GenericIPAddressField()
    reason = models.CharField(max_length=50, choices=REASON_CHOICES)
    detected_at = models.DateTimeField(auto_now_add=True)
    request_count = models.IntegerField(default=0)
    is_blocked = models.BooleanField(default=False)
    details = models.JSONField(blank=True, null=True)  # Store additional detection details

    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['detected_at']),
            models.Index(fields=['is_blocked']),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.get_reason_display()}"


class IPGeolocationCache(models.Model):
    """Cache for IP geolocation data to reduce API calls"""
    ip_address = models.GenericIPAddressField(unique=True)
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    isp = models.CharField(max_length=200, blank=True, null=True)
    cached_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        verbose_name = "IP Geolocation Cache"
        verbose_name_plural = "IP Geolocation Caches"

    def __str__(self):
        return f"{self.ip_address} - {self.country}, {self.city}"
