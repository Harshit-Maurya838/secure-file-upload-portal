from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from .models import SecurityEvent
from datetime import datetime, timedelta

class SecurityLogsViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('security_logs')
        
        # Create users
        self.staff_user = User.objects.create_user(username='staff', password='password', is_staff=True)
        self.normal_user = User.objects.create_user(username='user', password='password', is_staff=False)
        
        # Create some security events
        self.event1 = SecurityEvent.objects.create(
            event_type='MALWARE_DETECTED',
            user=self.normal_user,
            ip_address='192.168.1.1',
            file_name='virus.exe',
            details='EICAR test file'
        )
        self.event2 = SecurityEvent.objects.create(
            event_type='DOWNLOAD',
            user=self.staff_user,
            ip_address='10.0.0.1',
            file_name='report.pdf',
            details='Safe download'
        )
        # Hack to set timestamp in the past (auto_now_add makes it hard to set on create)
        self.event2.timestamp = datetime.now() - timedelta(days=2)
        self.event2.save()

    def test_access_anonymous(self):
        response = self.client.get(self.url)
        # Should redirect to login
        self.assertNotEqual(response.status_code, 200)
        self.assertTrue(response.status_code in [302, 403]) # Helper decorates might redirect or 403 depending on config

    def test_access_normal_user(self):
        self.client.login(username='user', password='password')
        response = self.client.get(self.url)
        # Should be forbidden
        self.assertTrue(response.status_code in [302, 403]) # staff_member_required usually redirects to login if not staff, or raises 403?
        # Standard staff_member_required redirects to login with ?next= if not staff.
        # Let's check if it redirects to login
        if response.status_code == 302:
            self.assertIn('login', response.url)

    def test_access_staff_user(self):
        self.client.login(username='staff', password='password')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'uploads/security_logs.html')
        self.assertContains(response, 'virus.exe')
        self.assertContains(response, 'report.pdf')

    def test_filter_event_type(self):
        self.client.login(username='staff', password='password')
        response = self.client.get(self.url, {'event_type': 'MALWARE_DETECTED'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'virus.exe')
        self.assertNotContains(response, 'report.pdf')

    def test_filter_user(self):
        self.client.login(username='staff', password='password')
        response = self.client.get(self.url, {'user': 'staff'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'report.pdf')
        self.assertNotContains(response, 'virus.exe')

    def test_filter_ip(self):
        self.client.login(username='staff', password='password')
        response = self.client.get(self.url, {'ip': '192.168.1.1'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'virus.exe')
        self.assertNotContains(response, 'report.pdf')

    def test_filter_date(self):
        self.client.login(username='staff', password='password')
        # event2 is 2 days ago. event1 is today.
        today = datetime.now().strftime('%Y-%m-%d')
        response = self.client.get(self.url, {'date_min': today})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'virus.exe')
        self.assertNotContains(response, 'report.pdf')

    def test_csv_export(self):
        self.client.login(username='staff', password='password')
        response = self.client.get(self.url, {'export': 'csv'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        content = response.content.decode('utf-8')
        self.assertIn('Timestamp,Event Type,User', content)
        self.assertIn('virus.exe', content)
        self.assertIn('report.pdf', content)

    def test_pagination(self):
        self.client.login(username='staff', password='password')
        # Create 30 events
        for i in range(30):
            SecurityEvent.objects.create(
                event_type='DOWNLOAD',
                user=self.staff_user,
                ip_address=f'10.0.0.{i}',
                file_name=f'file_{i}.txt',
                details='Download'
            )
        
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        # Should show 25 items (plus header/etc)
        # Paginator defaults to 25 in views.py
        self.assertEqual(len(response.context['page_obj']), 25)
        
        response = self.client.get(self.url, {'page': 2})
        self.assertEqual(response.status_code, 200)
        # Should show remaining items (30+2 existing = 32 total, so 7 on page 2)
        self.assertEqual(len(response.context['page_obj']), 7)
