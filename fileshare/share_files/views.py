import uuid
import os
import base64
from datetime import datetime
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.contrib.auth.hashers import check_password
from datetime import datetime
from django.core.files.storage import FileSystemStorage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from django.core.files.base import ContentFile
from django.http import HttpResponse
import base64

def user_profile(user_id):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT user_name,user_role
            FROM users
            WHERE user_id=%s
        """, [user_id])
        row = cursor.fetchone()
        if row:
            return {'user_name': row[0], 'user_role': row[1]}
        else:
            return {'user_name': '', 'user_role': ''}

def get_file_type_counts(user_id):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT doc_type, COUNT(*)
            FROM documents
            WHERE uploaded_user=%s
            GROUP BY doc_type
        """, [user_id])
        return cursor.fetchall()


def decrypt_and_download(request, doc_id):
    with connection.cursor() as cursor:
        # Fetch file details and encryption info from DB
        cursor.execute("""
            SELECT doc_name, encryption_key, doc_type
            FROM documents
            WHERE doc_id=%s
        """, [doc_id])
        row = cursor.fetchone()
        if not row:
            return HttpResponse("File not found", status=404)

        doc_name, encryption_key, doc_type = row

        # Split key, nonce, tag
        key_b64, nonce_b64, tag_b64 = encryption_key.split(':')
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)

        # Read encrypted file from disk
        encrypted_filename = f"enc_{doc_name}"
        file_path = os.path.join('media/uploads/', encrypted_filename)
        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Return file as download
        response = HttpResponse(plaintext, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{doc_name}"'
        return response


def get_uploaded_files(user_id, search_query='', file_type_filter=''):
    with connection.cursor() as cursor:
        query = """
            SELECT doc_id,doc_name, doc_type, uploaded_time
            FROM documents
            WHERE uploaded_user=%s
        """
        params = [user_id]

        if file_type_filter:
            query += " AND doc_type=%s"
            params.append(file_type_filter)

        if search_query:
            query += " AND (LOWER(doc_name) LIKE %s OR CAST(uploaded_time AS TEXT) LIKE %s)"
            params.extend([f'%{search_query.lower()}%', f'%{search_query}%'])

        query += " ORDER BY uploaded_time DESC"

        cursor.execute(query, params)
        return cursor.fetchall()

def home(request):
    user_id = request.session.get('user_id')
    user_name = ''
    role = ''
    org_tag=''
    show_toast = False
    error_message = ''
    uploaded_files = []
    user_file_types = []
    file_type_counts = get_file_type_counts(user_id)
    if user_id:
        with connection.cursor() as cursor:
            cursor.execute("SELECT user_name, user_role,org_tag FROM users WHERE user_id=%s", [user_id])
            row = cursor.fetchone()
            if row:
                user_name, role,org_tag = row
        search_query = request.GET.get('q', '').strip()
        selected_file_type = request.GET.get('file_type', '').strip()
        uploaded_files = get_uploaded_files(user_id, search_query,selected_file_type)

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT DISTINCT doc_type
                FROM documents
                WHERE uploaded_user=%s
            """, [user_id])
            user_file_types = [row[0] for row in cursor.fetchall()]


    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        file_name = '.'.join(uploaded_file.name.split('.')[:-1])
        file_size= uploaded_file.size
        file_extension = uploaded_file.name.split('.')[-1].lower()  # gives 'pdf'
        uploaded_time = datetime.now()
        doc_id = str(uuid.uuid4())  # generate unique doc_id
        with connection.cursor() as cursor:
            cursor.execute("SELECT allowed_file_type,file_size FROM organization WHERE org_tag=%s", [org_tag])
            row = cursor.fetchone()
            if row:
                allowed_types = row[0]  # e.g., '{pdf,jpg,png}'
                file_size_limit = row[1]  # e.g., 10485760 for 10MB

                if file_extension not in allowed_types:
                    error_message = f"Invalid file type: {file_extension} is not allowed for organization {org_tag}"
                elif file_size > file_size_limit:
                    error_message = f"File too large: {file_size} bytes (max allowed 5mb)"
                else:
                    key = os.urandom(32)  # 256-bit key
                    nonce = os.urandom(12)  # GCM recommended 96-bit nonce
                    plaintext = uploaded_file.read()

                    # Encrypt using AES‑256‑GCM 
                    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
                    encryptor = cipher.encryptor()
                    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                    tag = encryptor.tag  # authentication tag

                    # Save encrypted file (you could also store tag+nonce together, but let's keep them separate)
                    encrypted_filename = f"enc_{file_name}"        
                    key_b64 = base64.b64encode(key).decode('utf-8')
                    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
                    tag_b64 = base64.b64encode(tag).decode('utf-8')

                    # Insert details into documents table
                    with connection.cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO documents (doc_id, doc_name, doc_title, doc_type, doc_group, 
                                                uploaded_user, encryption_key, file_senstivity, 
                                                uploaded_time, org_tag)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, [
                            doc_id,                  # doc_id
                            file_name,               # doc_name
                            '',                      # doc_title (empty or default)
                            file_extension,               # doc_type
                            '',                      # doc_group
                            user_id,                 # uploaded_user (from session)
                            key_b64 + ':' + nonce_b64 + ':' + tag_b64,                      # encryption_key
                            'High',                      # file_sensitivity
                            uploaded_time,           # uploaded_time
                            org_tag                     # org_tag
                        ])
                    fs = FileSystemStorage(location='media/uploads/')
                    fs.save(encrypted_filename, ContentFile(ciphertext))
                    show_toast = True  # or redirect elsewhere after upload

    return render(request, 'home.html', {'user_name': user_name, 
                                         'role': role, 
                                         'show_toast': show_toast, 
                                         'error_message': error_message,
                                         'uploaded_files': uploaded_files,
                                         'user_file_types': user_file_types,
                                         'file_type_counts': file_type_counts})

# Create your views here.
def user_login(request):
    error = None
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        password = request.POST.get('password')
        with connection.cursor() as cursor:
            cursor.execute("SELECT user_password FROM users WHERE user_id=%s", [user_id])
            row = cursor.fetchone()
        if row and password:
            # Set session or custom login logic here
            request.session['user_id'] = user_id
            return redirect('home')
        else:
            error = "Invalid user ID or password"
    return render(request, 'login.html', {'error': error})

def logout_view(request):
    # Clear all session data (log the user out)
    request.session.flush()
    # Redirect to login page
    return redirect('login')

def shared_with_me(request):
    user_id = request.session.get('user_id')
    user_info = user_profile(user_id)
    return render(request, 'shared_with_me.html',{
        'user_name': user_info['user_name'], 
        'role': user_info['user_role'],
    })

def shared_by_me(request):
    user_id = request.session.get('user_id')
    user_info = user_profile(user_id)
    return render(request, 'shared_by_me.html',
        {
        'user_name': user_info['user_name'], 
        'role': user_info['user_role'],
    }
    )