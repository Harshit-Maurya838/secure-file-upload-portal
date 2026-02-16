from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from unittest.mock import patch, MagicMock
from .models import UploadedFile
from .utils import scan_file
import pyclamd

class ClamAVUtilsTests(TestCase):
    @patch('uploads.utils.get_clam_daemon')
    def test_scan_file_clean(self, mock_get_daemon):
        # Mock daemon
        mock_daemon = MagicMock()
        mock_daemon.scan_stream.return_value = None  # Clean
        mock_get_daemon.return_value = mock_daemon

        file = SimpleUploadedFile("clean.txt", b"content")
        result = scan_file(file)
        self.assertTrue(result)
        mock_daemon.scan_stream.assert_called()

    @patch('uploads.utils.get_clam_daemon')
    def test_scan_file_infected(self, mock_get_daemon):
        # Mock daemon
        mock_daemon = MagicMock()
        mock_daemon.scan_stream.return_value = {'stream': ('FOUND', 'EICAR-Test-Signature')}
        mock_get_daemon.return_value = mock_daemon

        file = SimpleUploadedFile("infected.txt", b"virus_content")
        with self.assertRaises(ValidationError) as cm:
            scan_file(file)
        self.assertIn("Malware detected", str(cm.exception))

    @patch('uploads.utils.get_clam_daemon')
    def test_scan_file_scanner_error(self, mock_get_daemon):
        # Mock daemon
        mock_daemon = MagicMock()
        # pyclamd raises ConnectionError or BufferError usually, or we can mock a generic Exception
        # Investigating pyclamd source, it might raise ConnectionError.
        # Let's mock a generic Exception to test the catch-all in utils.py
        mock_daemon.scan_stream.side_effect = Exception("Scan failed")
        mock_get_daemon.return_value = mock_daemon

        file = SimpleUploadedFile("error.txt", b"content")
        with self.assertRaises(ValidationError) as cm:
            scan_file(file)
        self.assertIn("Error processing file scan", str(cm.exception))

    @patch('uploads.utils.get_clam_daemon')
    def test_scan_file_daemon_unavailable(self, mock_get_daemon):
        mock_get_daemon.return_value = None  # No daemon found

        file = SimpleUploadedFile("nofile.txt", b"content")
        with self.assertRaises(ValidationError) as cm:
            scan_file(file)
        self.assertIn("File scanner unavailable", str(cm.exception))


class ClamAVViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        from django.contrib.auth.models import User
        self.user = User.objects.create_user(username='testuser', password='password')
        self.client.login(username='testuser', password='password')
        self.url = reverse('upload_file')

    @patch('uploads.views.scan_file')
    @patch('uploads.views.move_to_clean')
    @patch('uploads.views.sanitize_file')
    def test_upload_view_clean(self, mock_sanitize, mock_move, mock_scan):
        mock_scan.return_value = True
        
        # Valid PDF file content (minimal) to pass magic check
        # PDF header is %PDF-
        pdf_content = b"%PDF-1.4\n..."
        file = SimpleUploadedFile("test.pdf", pdf_content, content_type="application/pdf")
        
        response = self.client.post(self.url, {'file': file, 'description': 'Clean file'})
        
        self.assertEqual(response.status_code, 302) # Redirects to file_list
        self.assertTrue(UploadedFile.objects.exists())
        instance = UploadedFile.objects.first()
        # In the test, we mock move_to_clean, so status might still be PENDING if the mock doesn't side_effect
        # But we assert that move_to_clean was called
        mock_scan.assert_called_once()
        mock_sanitize.assert_called_once()
        mock_move.assert_called_once()

    @patch('uploads.views.scan_file')
    def test_upload_view_infected(self, mock_scan):
        mock_scan.side_effect = ValidationError("Malware detected: EICAR")
        
        pdf_content = b"%PDF-1.4\n..."
        file = SimpleUploadedFile("infected.pdf", pdf_content, content_type="application/pdf")
        
        response = self.client.post(self.url, {'file': file, 'description': 'Infected file'})
        
        self.assertEqual(response.status_code, 200) # Re-renders form
        self.assertFalse(UploadedFile.objects.exists()) # Should be deleted from DB
        self.assertContains(response, "Malware detected: EICAR")

class QuarantineTests(TestCase):
    def test_file_path_quarantine(self):
        # Test that new files go to quarantine
        # Need to mock verify_file to avoid magic check or use valid file
        
        # Manually creating model instance to check upload_to
        from .models import UploadedFile
        import uuid
        instance = UploadedFile()
        filename = "test.txt"
        path = instance.file.field.upload_to(instance, filename)
        self.assertTrue(path.startswith('quarantine/'))

    @patch('uploads.utils.get_clam_daemon')
    def test_move_to_clean(self, mock_get_daemon):
        # Test utils.move_to_clean logic directly
        from .utils import move_to_clean
        from django.conf import settings
        import os
        import shutil

        # Create a dummy file in quarantine
        quarantine_dir = os.path.join(settings.MEDIA_ROOT, 'quarantine')
        os.makedirs(quarantine_dir, exist_ok=True)
        filename = "clean_test.txt"
        file_path = os.path.join(quarantine_dir, filename)
        with open(file_path, 'w') as f:
            f.write("content")
        
        # Create model instance
        instance = UploadedFile.objects.create(
            file=os.path.join('quarantine', filename),
            status='PENDING'
        )

        # Execute move
        move_to_clean(instance)

        # Check DB
        instance.refresh_from_db()
        self.assertEqual(instance.status, 'CLEAN')
        self.assertTrue(instance.file.name.startswith('uploads/'))
        
        # Check Filesystem
        new_path = os.path.join(settings.MEDIA_ROOT, 'uploads', filename)
        self.assertTrue(os.path.exists(new_path))
        self.assertFalse(os.path.exists(file_path))

        # Cleanup
        if os.path.exists(new_path):
            os.remove(new_path)

class CDRTests(TestCase):
    def test_sanitize_image(self):
        from PIL import Image
        from .utils import sanitize_file
        import os
        from django.conf import settings

        # Create dummy image with metadata (hard to mock metadata easily, so just check it runs and re-saves)
        img = Image.new('RGB', (100, 100), color = 'red')
        filename = "test_image.jpg"
        path = os.path.join(settings.MEDIA_ROOT, 'quarantine', filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        img.save(path)

        instance = UploadedFile.objects.create(file=path, status='PENDING')
        
        # Run sanitize
        sanitize_file(instance)
        
        # Check if file still exists and is valid image
        self.assertTrue(os.path.exists(path))
        with Image.open(path) as img2:
            self.assertEqual(img2.mode, 'RGB')

        # Cleanup
        if os.path.exists(path):
            os.remove(path)

    def test_sanitize_pdf(self):
        from pypdf import PdfWriter
        from .utils import sanitize_file
        import os
        from django.conf import settings

        # Create dummy PDF
        filename = "test.pdf"
        path = os.path.join(settings.MEDIA_ROOT, 'quarantine', filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        with open(path, "wb") as f:
            writer.write(f)

        instance = UploadedFile.objects.create(file=path, status='PENDING')

        # Run sanitize
        sanitize_file(instance)

        # Check if file still exists and is valid PDF
        self.assertTrue(os.path.exists(path))
        # Verify functionality (size might change lightly)
        self.assertGreater(os.path.getsize(path), 0)

        # Cleanup
        if os.path.exists(path):
            os.remove(path)

class ProtectedStorageTests(TestCase):
    def setUp(self):
        self.client = Client()
        from django.contrib.auth.models import User
        self.user = User.objects.create_user(username='testuser', password='password')
        self.url_upload = reverse('upload_file')

    def test_download_clean_file_authenticated(self):
        self.client.login(username='testuser', password='password')
        
        # Create a clean file
        f = SimpleUploadedFile("clean.txt", b"content")
        instance = UploadedFile.objects.create(file=f, status='CLEAN')
        
        url = reverse('download_file', args=[instance.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"content")
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="{instance.file.name.split("/")[-1]}"')

    def test_download_pending_file_authenticated(self):
        self.client.login(username='testuser', password='password')
        
        # Create a pending file
        f = SimpleUploadedFile("pending.txt", b"content")
        instance = UploadedFile.objects.create(file=f, status='PENDING')
        
        url = reverse('download_file', args=[instance.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 404) # Should not be found/available

    def test_download_file_unauthenticated(self):
        # Create a clean file
        f = SimpleUploadedFile("clean.txt", b"content")
        instance = UploadedFile.objects.create(file=f, status='CLEAN')
        
        url = reverse('download_file', args=[instance.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 302) # Redirect to login

class SecurityLoggingTests(TestCase):
    def setUp(self):
        self.client = Client()
        from django.contrib.auth.models import User
        self.user = User.objects.create_user(username='testuser', password='password')
        self.url_upload = reverse('upload_file')

    @patch('uploads.views.scan_file')
    def test_log_malware_event(self, mock_scan):
        self.client.login(username='testuser', password='password')
        mock_scan.side_effect = ValidationError("Malware detected: EICAR")
        
        pdf_content = b"%PDF-1.4\n..."
        file = SimpleUploadedFile("infected.pdf", pdf_content, content_type="application/pdf")
        
        self.client.post(self.url_upload, {'file': file, 'description': 'Infected'})
        
        from .models import SecurityEvent
        event = SecurityEvent.objects.last()
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, 'MALWARE_DETECTED')
        self.assertIn("EICAR", event.details)
        self.assertEqual(event.user, self.user)

    def test_log_download_event(self):
        self.client.login(username='testuser', password='password')
        
        # Create clean file
        f = SimpleUploadedFile("clean.txt", b"content")
        instance = UploadedFile.objects.create(file=f, status='CLEAN')
        
        url = reverse('download_file', args=[instance.id])
        self.client.get(url)
        
        from .models import SecurityEvent
        event = SecurityEvent.objects.last()
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, 'DOWNLOAD')
        self.assertEqual(event.user, self.user)
