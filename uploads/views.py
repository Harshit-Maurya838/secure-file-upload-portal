from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .forms import UploadFileForm
from .models import UploadedFile


from django_ratelimit.decorators import ratelimit

from .utils import scan_file, move_to_clean, sanitize_file, log_security_event
from django.core.exceptions import ValidationError

@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@login_required
def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            # Save initially to quarantine (status=PENDING)
            # manually handling save to inject original_filename
            instance = form.save(commit=False)
            
            # Sanitize and store original filename
            from django.utils.text import get_valid_filename
            original_name = request.FILES['file'].name
            instance.original_filename = get_valid_filename(original_name)
            
            instance.save()
            try:
                # Scan the file
                scan_file(instance.file)
                # Sanitize (CDR)
                sanitize_file(instance)
                # If clean, move to clean storage
                move_to_clean(instance)
                return redirect('file_list')
            except ValidationError as e:
                # If infected or error, delete the file and the instance
                virus_name = str(e)
                if "Malware detected" in virus_name:
                    log_security_event('MALWARE_DETECTED', request, instance.file.name, virus_name)
                
                instance.file.delete(save=False)
                instance.delete()
                form.add_error('file', e.message)
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})

from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404
from .models import UploadedFile

@login_required
def download_file(request, file_id):
    instance = get_object_or_404(UploadedFile, id=file_id)
    
    # Access control: ensure file is CLEAN
    if instance.status != 'CLEAN':
        raise Http404("File is not available for download.")
        
    try:
        response = FileResponse(instance.file.open('rb'), as_attachment=True, filename=instance.original_filename)
        log_security_event('DOWNLOAD', request, instance.file.name, "File downloaded successfully")
        return response
    except FileNotFoundError:
        raise Http404("File not found on server.")

@login_required
def file_list(request):
    files = UploadedFile.objects.filter(status='CLEAN').order_by('-uploaded_at')
    return render(request, 'uploader/file_list.html', {'files': files})
