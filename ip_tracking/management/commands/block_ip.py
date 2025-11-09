from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Manage IP address blocking'

    def add_arguments(self, parser):
        parser.add_argument('action', choices=['add', 'remove', 'list'], help='Action to perform')
        parser.add_argument('ip_address', nargs='?', type=str, help='IP address to manage')
        parser.add_argument('--reason', type=str, help='Reason for blocking')
        parser.add_argument('--days', type=int, default=30, help='Number of days to block (default: 30)')

    def handle(self, *args, **options):
        action = options['action']
        ip_address = options.get('ip_address')
        reason = options.get('reason', '')
        days = options['days']

        if action == 'add':
            self.add_block(ip_address, reason, days)
        elif action == 'remove':
            self.remove_block(ip_address)
        elif action == 'list':
            self.list_blocks()

    def add_block(self, ip_address, reason, days):
        if not ip_address:
            raise CommandError("IP address is required for add action")

        try:
            expires_at = timezone.now() + timedelta(days=days)
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'reason': reason or f'Manually blocked for {days} days',
                    'expires_at': expires_at
                }
            )
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully blocked IP: {ip_address} for {days} days')
                )
            else:
                blocked_ip.is_active = True
                blocked_ip.expires_at = expires_at
                blocked_ip.reason = reason or blocked_ip.reason
                blocked_ip.save()
                self.stdout.write(
                    self.style.SUCCESS(f'Updated existing block for IP: {ip_address}')
                )
                
        except Exception as e:
            raise CommandError(f'Error blocking IP {ip_address}: {str(e)}')

    def remove_block(self, ip_address):
        if not ip_address:
            raise CommandError("IP address is required for remove action")

        try:
            deleted_count = BlockedIP.objects.filter(ip_address=ip_address).update(is_active=False)
            if deleted_count > 0:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully unblocked IP: {ip_address}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_address} was not found in blocklist')
                )
                
        except Exception as e:
            raise CommandError(f'Error unblocking IP {ip_address}: {str(e)}')

    def list_blocks(self):
        active_blocks = BlockedIP.objects.filter(is_active=True)
        
        if not active_blocks:
            self.stdout.write("No active IP blocks found")
            return

        self.stdout.write("Active IP Blocks:")
        self.stdout.write("-" * 80)
        for block in active_blocks:
            status = f"expires {block.expires_at}" if block.expires_at else "permanent"
            self.stdout.write(
                f"{block.ip_address:15} | {status:20} | {block.reason}"
            )
