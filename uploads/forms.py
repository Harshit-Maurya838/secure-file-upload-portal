import os
import magic
from django import forms
from .models import UploadedFile


class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['file', 'description']
    def clean_file(self):
        file = self.cleaned_data.get('file')
        limit = 5 * 1024 * 1024  # 5 MB
        if file:
            if file.size > limit:
                raise forms.ValidationError('File too large. Size should not exceed 5 MiB.')
            # File path Validation
            allowed_extensions = ['.jpg', '.jpeg', '.png', '.pdf']
            ext = os.path.splitext(file.name)[1].lower()
            if ext not in allowed_extensions:
                raise forms.ValidationError('Unsupported file extension. Allowed: jpg, jpeg, png, pdf.')
            
            # Validate MIME type using magic bytes
            valid_mime_types = ['image/jpeg', 'image/png', 'application/pdf']
            file_mime_type = magic.from_buffer(file.read(2048), mime=True)
            file.seek(0)
            
            if file_mime_type not in valid_mime_types:
                raise forms.ValidationError('Invalid file type detected. Please upload a valid image or PDF.')
            
        return file
