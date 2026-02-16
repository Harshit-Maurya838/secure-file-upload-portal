import pyclamd
import logging
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

def get_clam_daemon():
    """
    Connect to ClamAV daemon.
    Checks for socket first, then network.
    """
    try:
        # Try local socket
        cd = pyclamd.ClamdUnixSocket()
        if cd.ping():
            return cd
    except pyclamd.ConnectionError:
        pass

    try:
        # Try network socket (default localhost:3310)
        cd = pyclamd.ClamdNetworkSocket()
        if cd.ping():
            return cd
    except pyclamd.ConnectionError:
        pass

    return None

def scan_file(file_obj):
    """
    Scans a file for malware using ClamAV.
    Raises ValidationError if infected or scanner is unavailable (fail-closed).
    """
    cd = get_clam_daemon()
    
    if not cd:
        logger.error("ClamAV daemon not available. Upload rejected (Fail-Closed).")
        raise ValidationError("File scanner unavailable. Please try again later.")

    try:
        # Scan stream
        result = cd.scan_stream(file_obj.read())
        # Reset file pointer for subsequent saving
        file_obj.seek(0)
    except Exception as e:
        logger.error(f"Error during file scan: {str(e)}")
        raise ValidationError("Error processing file scan.")

    if result is None:
        # No virus found
        return True
    
    # Virus found
    # result structure is { 'stream': ('FOUND', 'VirusName') }
    virus_name = list(result.values())[0][1]
    logger.warning(f"Malware detected during upload: {virus_name}")
    raise ValidationError(f"Malware detected: {virus_name}")

def move_to_clean(instance):
    """
    Moves a file from quarantine to the clean directory and updates status.
    """
    import os
    import shutil
    from django.conf import settings

    if instance.status != 'PENDING':
        return

    old_path = instance.file.path
    if not os.path.exists(old_path):
        raise ValidationError("File not found in quarantine.")

    # Define new path (e.g., uploads/clean/)
    new_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
    os.makedirs(new_dir, exist_ok=True)
    
    new_filename = os.path.basename(old_path)
    new_path = os.path.join(new_dir, new_filename)

    try:
        shutil.move(old_path, new_path)
        # Update model field to point to new location relative to MEDIA_ROOT
        instance.file.name = os.path.join('uploads', new_filename)
        instance.status = 'CLEAN'
        instance.save()
    except Exception as e:
        logger.error(f"Error moving file to clean storage: {str(e)}")
        raise ValidationError("Error processing file.")

def sanitize_file(instance):
    """
    Sanitizes the file by reconstructing it.
    - Images: Re-encoded using Pillow (strips EXIF).
    - PDFs: Re-saved using pypdf.
    - Others: No action (or reject if strict).
    """
    from PIL import Image
    from pypdf import PdfReader, PdfWriter
    import mimetypes

    file_path = instance.file.path
    mime_type, _ = mimetypes.guess_type(file_path)

    try:
        if mime_type and mime_type.startswith('image/'):
            # Sanitize Image
            with Image.open(file_path) as img:
                data = list(img.getdata())
                image_without_exif = Image.new(img.mode, img.size)
                image_without_exif.putdata(data)
                image_without_exif.save(file_path)
                
        elif mime_type == 'application/pdf':
            # Sanitize PDF
            reader = PdfReader(file_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            
            with open(file_path, "wb") as f:
                writer.write(f)
                
    except Exception as e:
        logger.error(f"Error sanitizing file {file_path}: {str(e)}")
        raise ValidationError("File sanitization failed.")

def log_security_event(event_type, request, file_name=None, details=None):
    """
    Logs a security event to the database.
    """
    from .models import SecurityEvent
    
    ip = request.META.get('REMOTE_ADDR')
    user = request.user if request.user.is_authenticated else None
    
    SecurityEvent.objects.create(
        event_type=event_type,
        user=user,
        ip_address=ip,
        file_name=file_name or '',
        details=details or ''
    )


