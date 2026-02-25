from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .forms import UploadFileForm
from .models import UploadedFile
from django.contrib import messages
from django_ratelimit.decorators import ratelimit

from .utils import scan_file, move_to_clean, sanitize_file, log_security_event
from django.core.exceptions import ValidationError
from django.contrib.admin.views.decorators import staff_member_required
from django.core.paginator import Paginator
from django.http import HttpResponse
import csv
from .models import SecurityEvent
from datetime import datetime


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
                messages.success(request, f"Upload Successful: File '{instance.original_filename}' has been safely stored.")
                return redirect('file_list')
            except ValidationError as e:
                # If infected or error, delete the file and the instance
                virus_name = str(e)
                if "Malware detected" in virus_name:
                    log_security_event('MALWARE_DETECTED', request, instance.file.name, virus_name)
                
                instance.file.delete(save=False)
                instance.delete()
                messages.error(request, f"Malware Detected / Upload Rejected: {e.message}")
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
        messages.success(request, f"Download initiated for {instance.original_filename}.")
        response = FileResponse(instance.file.open('rb'), as_attachment=True, filename=instance.original_filename)
        log_security_event('DOWNLOAD', request, instance.file.name, "File downloaded successfully")
        return response
    except FileNotFoundError:
        messages.error(request, "File not found on server.")
        raise Http404("File not found on server.")

@login_required
def file_list(request):
    files = UploadedFile.objects.filter(status='CLEAN').order_by('-uploaded_at')
    return render(request, 'uploader/file_list.html', {'files': files})

@staff_member_required
def security_logs(request):
    # Filter setup
    events = SecurityEvent.objects.all().order_by('-timestamp')
    
    event_type = request.GET.get('event_type')
    if event_type:
        events = events.filter(event_type=event_type)
        
    user_query = request.GET.get('user')
    if user_query:
        events = events.filter(user__username__icontains=user_query)
        
    ip_query = request.GET.get('ip')
    if ip_query:
        events = events.filter(ip_address__icontains=ip_query)
        
    date_min = request.GET.get('date_min')
    if date_min:
        try:
            events = events.filter(timestamp__gte=date_min)
        except ValidationError:
            pass # Ignore invalid date

    date_max = request.GET.get('date_max')
    if date_max:
         try:
            # Add time to include the whole day
            events = events.filter(timestamp__lte=date_max + " 23:59:59")
         except ValidationError:
            pass

    # CSV Export
    if request.GET.get('export') == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="security_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Timestamp', 'Event Type', 'User', 'IP Address', 'File Name', 'Details'])
        
        for event in events:
            writer.writerow([
                event.timestamp,
                event.event_type,
                event.user.username if event.user else 'Anonymous',
                event.ip_address,
                event.file_name,
                event.details
            ])
            
        return response

    # Pagination
    paginator = Paginator(events, 25) # 25 events per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Event types for filter dropdown
    event_types = SecurityEvent.EVENT_TYPES

    return render(request, 'uploads/security_logs.html', {
        'page_obj': page_obj,
        'event_types': event_types,
    })

