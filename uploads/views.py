from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .forms import UploadFileForm
from .models import UploadedFile


from django_ratelimit.decorators import ratelimit

from .utils import scan_file, move_to_clean, sanitize_file
from django.core.exceptions import ValidationError

@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@login_required
def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            # Save initially to quarantine (status=PENDING)
            instance = form.save()
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
                instance.file.delete(save=False)
                instance.delete()
                form.add_error('file', e.message)
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})


@login_required
def file_list(request):
    files = UploadedFile.objects.all().order_by('-uploaded_at')
    return render(request, 'uploader/file_list.html', {'files': files})
