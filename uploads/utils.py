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
