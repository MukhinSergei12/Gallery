from django.shortcuts import render, redirect
from django.contrib.auth import login, logout as django_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.conf import settings
from urllib.parse import urlencode
import requests
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseForbidden


def index(request):
    return render(request, "accounts/index.html")


def google_login(request):
    params = {
        "response_type": "code",
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "scope": "openid email profile https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata https://www.googleapis.com/auth/photoslibrary.appendonly",
        "access_type": "offline",
        "prompt": "consent"
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return redirect(auth_url)

def google_callback(request):
    code = request.GET.get('code')
    if not code:
        return redirect('google-login')

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        'code': code,
        'client_id': settings.GOOGLE_CLIENT_ID,
        'client_secret': settings.GOOGLE_CLIENT_SECRET,
        'redirect_uri': settings.GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    token_resp = requests.post(token_url, data=data)
    token_data = token_resp.json()
    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')

    userinfo_url = "https://openidconnect.googleapis.com/v1/userinfo"
    headers = {'Authorization': f'Bearer {access_token}'}
    userinfo = requests.get(userinfo_url, headers=headers).json()
    email = userinfo.get('email')
    name = userinfo.get('name', '')

    user, _ = User.objects.get_or_create(username=email, defaults={'email': email, 'first_name': name})
    login(request, user)
    request.session['access_token'] = access_token
    request.session['refresh_token'] = refresh_token
    return redirect('gallery')


@login_required
def logout(request):
    django_logout(request)
    return redirect('home')


@login_required
def gallery(request):
    access_token = get_valid_access_token(request)
    if not access_token:
        return redirect('google-login')
    headers = {'Authorization': f'Bearer {access_token}'}
    url = 'https://photoslibrary.googleapis.com/v1/mediaItems?pageSize=100'
    resp = requests.get(url, headers=headers)
    items = resp.json().get('mediaItems', [])
    return render(request, 'accounts/gallery.html', {'media_items': items})


@login_required
def upload(request):
    uploaded_url = None
    if request.method == 'POST' and request.FILES.get('photo'):
        photo_file = request.FILES['photo']
        access_token = get_valid_access_token(request)
        if not access_token:
            return redirect('google-login')

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-type': 'application/octet-stream',
            'X-Goog-Upload-File-Name': photo_file.name,
            'X-Goog-Upload-Protocol': 'raw',
        }
        upload_token_resp = requests.post(
            'https://photoslibrary.googleapis.com/v1/uploads',
            headers=headers,
            data=photo_file.read()
        )

        if upload_token_resp.status_code != 200:
            return render(request, 'accounts/upload.html', {
                'uploaded_url': None,
                'error': 'Не удалось загрузить файл. Проверьте токен или размер файла.'
            })

        upload_token = upload_token_resp.text.strip()

        create_headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        json_data = {
            'newMediaItems': [{
                'description': 'Uploaded via Django',
                'simpleMediaItem': {
                    'uploadToken': upload_token,
                }
            }]
        }

        create_resp = requests.post(
            'https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate',
            headers=create_headers,
            json=json_data
        )

        if create_resp.status_code == 200:
            items = create_resp.json().get('newMediaItemResults', [])
            if items and 'mediaItem' in items[0]:
                uploaded_url = items[0]['mediaItem'].get('baseUrl')
            else:
                return render(request, 'accounts/upload.html', {
                    'error': 'Фотография не была создана. Попробуйте позже.'
                })
        else:
            return render(request, 'accounts/upload.html', {
                'error': 'Ошибка при создании фотографии. Проверьте токен доступа.'
            })

    return render(request, 'accounts/upload.html', {'uploaded_url': uploaded_url})


def get_valid_access_token(request):
    access_token = request.session.get('access_token')
    refresh_token = request.session.get('refresh_token')

    test_headers = {'Authorization': f'Bearer {access_token}'}
    test_resp = requests.get("https://www.googleapis.com/oauth2/v1/tokeninfo", headers=test_headers)

    if test_resp.status_code == 200:
        return access_token  # Всё ок, токен рабочий

    refresh_url = 'https://oauth2.googleapis.com/token'
    refresh_data = {
        'client_id': settings.GOOGLE_CLIENT_ID,
        'client_secret': settings.GOOGLE_CLIENT_SECRET,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token'
    }

    refresh_resp = requests.post(refresh_url, data=refresh_data)
    if refresh_resp.status_code == 200:
        new_token = refresh_resp.json().get('access_token')
        request.session['access_token'] = new_token
        return new_token
    else:
        django_logout(request)
        return None
