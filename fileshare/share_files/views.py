import uuid
import os
import base64
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.contrib.auth.hashers import check_password
from datetime import timedelta, datetime
from django.core.files.storage import FileSystemStorage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from django.core.files.base import ContentFile
from django.http import HttpResponse


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

from datetime import timedelta, datetime

def share_document(request):
    if request.method == 'POST':
        doc_id = request.POST.get('doc_id')
        user_ids_raw = request.POST.get('user_ids', '')
        duration_hours = int(request.POST.get('duration', '1'))

        # split user IDs and clean them
        user_ids = [uid.strip() for uid in user_ids_raw.split(',') if uid.strip()]

        # get current user's org_tag
        user_id = request.session.get('user_id')
        with connection.cursor() as cursor:
            cursor.execute("SELECT org_tag FROM users WHERE user_id=%s", [user_id])
            row = cursor.fetchone()
            org_tag = row[0] if row else None

        # get valid users in same organization
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT user_id FROM users WHERE user_id = ANY(%s) AND org_tag=%s
            """, [user_ids, org_tag])
            valid_user_ids = [r[0] for r in cursor.fetchall()]

        shared_at = datetime.now()
        time_limit = timedelta(hours=duration_hours)

        # insert one row per valid user
        with connection.cursor() as cursor:
            for shared_user_id in valid_user_ids:
                cursor.execute("""
                    INSERT INTO shared_documents (doc_id, shared_user_id, shared_at, shared_status, download_count, current_download_count, time_limit,shared_by_user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s,%s)
                """, [
                    doc_id, shared_user_id, shared_at, 'Internal', 3, 0, time_limit,user_id
                ])
        return redirect(request.META.get('HTTP_REFERER', 'home'))

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

from datetime import datetime, timedelta
from django.http import HttpResponse, Http404

def shared_with_me_table(user_id,search_query=''):
    with connection.cursor() as cursor:
        if search_query:
            cursor.execute("""
                SELECT d.doc_id,d.doc_name, d.doc_type, s.shared_at, s.shared_by_user_id
                FROM shared_documents s
                JOIN documents d ON s.doc_id = d.doc_id
                WHERE s.shared_user_id = %s
                  AND s.shared_status = %s
                  AND (LOWER(d.doc_name) LIKE %s OR LOWER(d.doc_type) LIKE %s)
                ORDER BY s.shared_at DESC
            """, [
                user_id, 'Internal',
                f'%{search_query.lower()}%', f'%{search_query.lower()}%'
            ])
            return cursor.fetchall()
        else:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT d.doc_id,d.doc_name, d.doc_type, s.shared_at, s.shared_by_user_id
                    FROM shared_documents s
                    JOIN documents d ON s.doc_id = d.doc_id
                    WHERE s.shared_user_id = %s and s.shared_status = 'Internal'
                    ORDER BY s.shared_at DESC
                """, [user_id])
                return cursor.fetchall()


def shared_with_me(request):
    user_id = request.session.get('user_id')
    user_info = user_profile(user_id)
    search_query = request.GET.get('q', '').strip()
    shared_files = shared_with_me_table(user_id,search_query)

    if request.method == 'POST':
        access_link = request.POST.get('shared_link', '').strip()
        access_token = access_link.strip('/').split('/')[-1]

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT d.doc_id, d.doc_name, d.encryption_key, s.shared_at, s.time_limit, 
                       s.download_count, s.current_download_count
                FROM shared_documents s
                JOIN documents d ON s.doc_id = d.doc_id
                WHERE s.access_token=%s AND s.shared_user_id=%s
            """, [access_token, user_id])
            row = cursor.fetchone()

        if not row:
            return HttpResponse("You don't have access to this file.", status=403)

        doc_id, doc_name, encryption_key, shared_at, time_limit, download_count, current_download_count = row

        # Check expiry
        expires_at = shared_at + time_limit
        if datetime.now() > expires_at:
            return HttpResponse("Link has expired.", status=403)

        # Check download count
        if current_download_count >= download_count:
            return HttpResponse("Download limit exceeded.", status=403)

        # ✅ Update access_status and count
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE shared_documents
                SET current_download_count = current_download_count + 1,
                    access_status = %s
                WHERE access_token=%s AND shared_user_id=%s
            """, ['yes', access_token, user_id])

        # Decrypt file (reuse your decrypt logic inline)
        key_b64, nonce_b64, tag_b64 = encryption_key.split(':')
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)

        encrypted_filename = f"enc_{doc_name}"
        file_path = os.path.join('media/uploads/', encrypted_filename)
        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Send decrypted file
        response = HttpResponse(plaintext, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{doc_name}"'
        return response

    # GET: just render page
    return render(request, 'shared_with_me.html', {
        'user_name': user_info['user_name'],
        'role': user_info['user_role'],
        'shared_files': shared_files,
        'search_query': search_query,
    })








def shareable_organizations(user_id):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT org_tag FROM users WHERE user_id=%s
        """, [user_id])
        row = cursor.fetchone()
        if row and row[0]:
            org_tag = row[0]
        else:
            return []  # no org_tag → return empty
        # Now get shareable_organizations from organization table
        cursor.execute("""
            SELECT shareable_organizations
            FROM organization
            WHERE org_tag=%s
        """, [org_tag])
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]
        else:
            return []

def get_uploaded_filenames(user_id):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT doc_name
            FROM documents
            WHERE uploaded_user=%s
        """, [user_id])
        uploaded_filenames = [r[0] for r in cursor.fetchall()]
    return uploaded_filenames

def shared_documents(user_id):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT d.doc_id,d.doc_name, d.doc_type, s.shared_user_id, s.shared_at, s.shared_status, s.access_status,s.download_count,s.current_download_count
            FROM shared_documents s
            JOIN documents d ON s.doc_id = d.doc_id
            WHERE d.uploaded_user = %s
            ORDER BY s.shared_at DESC
        """, [user_id])
        return cursor.fetchall()

def get_shared_files_by_user(user_id, search_query='',selected_status=''):
    with connection.cursor() as cursor:
        query = """
            SELECT d.doc_id,d.doc_name, d.doc_type, s.shared_user_id, s.shared_at,s.shared_status, s.access_status,s.download_count,s.current_download_count
            FROM shared_documents s
            JOIN documents d ON s.doc_id = d.doc_id
            WHERE d.uploaded_user = %s
        """
        params = [user_id]
        if search_query:
            query += " AND (LOWER(d.doc_name) LIKE %s OR LOWER(s.shared_user_id) LIKE %s)"
            params += ['%' + search_query.lower() + '%', '%' + search_query.lower() + '%']

        if selected_status:
            query += " AND s.shared_status = %s"
            params.append(selected_status)

        query += " ORDER BY s.shared_at DESC"

        cursor.execute(query, params)
        return cursor.fetchall()

def filter_shared_by_me(user_id):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT enumlabel
            FROM pg_enum
            JOIN pg_type ON pg_enum.enumtypid = pg_type.oid
            WHERE pg_type.typname = 'share_status'
            ORDER BY enumsortorder
        """)
        rows = cursor.fetchall()
        return [row[0] for row in rows]

def create_shared_link(user_id, org_tag, file_name, user_ids_raw, start_date_str, end_date_str):
    user_ids = [u.strip() for u in user_ids_raw.split(',') if u.strip()]

    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')
    except Exception:
        start_date = end_date = datetime.now()
    time_limit = end_date - start_date

    # find doc_id of file uploaded by user
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT doc_id FROM documents
            WHERE doc_name=%s AND uploaded_user=%s
        """, [file_name, user_id])
        row = cursor.fetchone()
        doc_id = row[0] if row else None

    if doc_id:
        # generate single access token
        access_token = str(uuid.uuid4())

        for shared_user_id in user_ids:
            with connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO shared_documents (
                        doc_id, shared_user_id, shared_at, shared_status,
                        access_token, access_status, download_count, current_download_count, time_limit,shared_by_user_id
                    ) VALUES (%s, %s, NOW(), %s, %s, %s, %s, %s, %s,%s)
                """, [
                    doc_id, shared_user_id, 'External', access_token, 'no', 2, 0, time_limit,user_id
                ])

        # return the single generated link
        return f"/access/{access_token}/"
    else:
        return None


def shared_by_me(request):
    user_id = request.session.get('user_id')
    user_info = user_profile(user_id)
    shareable_orgs = shareable_organizations(user_id)
    uploaded_filenames = get_uploaded_filenames(user_id)
    shared_files = shared_documents(user_id)
    filter=filter_shared_by_me(user_id)
    search_query = request.GET.get('q', '').strip()
    selected_status = request.GET.get('status', '').strip()
    shared_files = get_shared_files_by_user(user_id, search_query, selected_status)

    generated_link = None
    if request.method == 'POST':
        org_tag = request.POST.get('org_tag')
        file_name = request.POST.get('file_name')
        user_ids_raw = request.POST.get('user_ids', '')
        start_date_str = request.POST.get('start_date')
        end_date_str = request.POST.get('end_date')

        generated_link = create_shared_link(
            user_id, org_tag, file_name, user_ids_raw, start_date_str, end_date_str
        )
    return render(request, 'shared_by_me.html',
        {
        'user_name': user_info['user_name'], 
        'role': user_info['user_role'],
        'shareable_orgs': shareable_orgs,
        'uploaded_filenames': uploaded_filenames,
        'shared_files':shared_files,
        'filter':filter,
        'generated_link': generated_link,
    }
    )