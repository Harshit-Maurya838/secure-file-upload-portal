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
        mock_daemon.scan_stream.side_effect = pyclamd.ScanError("Scan failed")
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
    def test_upload_view_clean(self, mock_scan):
        mock_scan.return_value = True
        
        # Valid PDF file content (minimal) to pass magic check
        # PDF header is %PDF-
        pdf_content = b"%PDF-1.4\n..."
        file = SimpleUploadedFile("test.pdf", pdf_content, content_type="application/pdf")
        
        response = self.client.post(self.url, {'file': file, 'description': 'Clean file'})
        
        self.assertEqual(response.status_code, 302) # Redirects to file_list
        self.assertTrue(UploadedFile.objects.exists())
        mock_scan.assert_called_once()

    @patch('uploads.views.scan_file')
    def test_upload_view_infected(self, mock_scan):
        mock_scan.side_effect = ValidationError("Malware detected: EICAR")
        
        pdf_content = b"%PDF-1.4\n..."
        file = SimpleUploadedFile("infected.pdf", pdf_content, content_type="application/pdf")
        
        response = self.client.post(self.url, {'file': file, 'description': 'Infected file'})
        
        self.assertEqual(response.status_code, 200) # Re-renders form
        self.assertFalse(UploadedFile.objects.exists())
        self.assertContains(response, "Malware detected: EICAR")
