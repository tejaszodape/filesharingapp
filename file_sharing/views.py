# views.py
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from .models import UserProfile
from kyber_py.kyber import Kyber512
from django.contrib.auth.decorators import login_required
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.core.cache import cache 
import random
import string
from django.core.mail import send_mail
from django.contrib import messages

@login_required
def dashboard(request):
    users = User.objects.exclude(id=request.user.id)
    shared_files = SharedFile.objects.filter(receiver=request.user).order_by('-created_at')
    sent_files = SharedFile.objects.filter(sender=request.user).order_by('-created_at')
    return render(request, 'dashboard.html', {'users': users, 'shared_files': shared_files, 'sent_files': sent_files})



@login_required
def home_view(request):
    return render(request, "home.html") 

def register(request):
    if request.method == 'POST':
        email= request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        request.session['username'] = username
        if username and password:
            user = User.objects.create_user(username=username, password=password,email=email)
            # Generate Kyber key pair
            public_key, private_key = Kyber512.keygen()
            ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
            ecdsa_public_key = ecdsa_private_key.public_key()
            ecdsa_private_bytes = ecdsa_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            ecdsa_public_bytes = ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            UserProfile.objects.create(
                user=user,
                  kyber_public_key=public_key, 
                  kyber_private_key=private_key,
                  ecdsa_private_key=ecdsa_private_bytes,
                  ecdsa_public_key=ecdsa_public_bytes
                  )
            user.save() 
            
            return redirect('register_face')
    return render(request, 'register.html')

# views.py
from django.contrib.auth import login, authenticate
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        request.session['username'] = username
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
           otp = generate_otp()
           cache.set(f"otp_{user.id}", otp, timeout=300)  # Store OTP for 5 minutes

            # Send OTP via email
           send_otp_email(user.email, otp)

            # Store user ID in session temporarily
           request.session["temp_user_id"] = user.id

           return redirect("verify_otp")  # Redirect to OTP verification page
        else:
            messages.error(request, "Invalid username or password.")
           
    return render(request, 'login.html')


# views.py
import os, json, base64
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from kyber_py.kyber import Kyber512
from .models import SharedFile, UserProfile
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from django.core.files.base import ContentFile
@login_required
def upload_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        # Get the receiver's username from POST data
        receiver_username = request.POST.get('receiver_username')
        # Look up the user by username instead of id
        receiver = get_object_or_404(User, username=receiver_username)
        file_obj = request.FILES['file']
        original_filename = file_obj.name

        # Read file content
        file_data = file_obj.read()

        # Generate a random AES key using Kyber encapsulation with the receiver's public key:
        receiver_profile = UserProfile.objects.get(user=receiver)
        aes_key, encapsulated_key = Kyber512.encaps(receiver_profile.kyber_public_key)

        # Encrypt the file with AES-GCM
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(file_data) + encryptor.finalize()
        tag = encryptor.tag

        # Sign the ciphertext using sender's ECDSA private key
        sender_profile = UserProfile.objects.get(user=request.user)
        sender_private_key = serialization.load_pem_private_key(
            sender_profile.ecdsa_private_key,
            password=None,
        )
        signature = sender_private_key.sign(
            ciphertext,
            ec.ECDSA(hashes.SHA256())
        )

        # Save the encrypted file to disk
        from django.core.files.base import ContentFile
        encrypted_file = ContentFile(ciphertext, name=original_filename + ".enc")

        # Create a SharedFile record
        shared_file = SharedFile.objects.create(
            sender=request.user,
            receiver=receiver,
            file=encrypted_file,
            original_filename=original_filename,
            nonce=nonce,
            tag=tag,
            encapsulated_key=encapsulated_key,
            signature=signature
        )
        return JsonResponse({'message': 'File shared successfully!', 'file_id': shared_file.id})
    return JsonResponse({'error': 'Invalid request'}, status=400)

from cryptography.exceptions import InvalidSignature
# views.py
from django.http import HttpResponse

@login_required
def download_file(request, file_id):
    shared_file = get_object_or_404(SharedFile, id=file_id, receiver=request.user)
    
    # Retrieve the stored metadata
    nonce = shared_file.nonce
    tag = shared_file.tag
    encapsulated_key = shared_file.encapsulated_key

    # Get the receiver's Kyber private key from their profile
    receiver_profile = UserProfile.objects.get(user=request.user)
    
    # Decapsulate to recover the AES key
    aes_key = Kyber512.decaps(receiver_profile.kyber_private_key, encapsulated_key)

    # Read the encrypted file content
    encrypted_data = shared_file.file.read()
       
       
    sender_profile = UserProfile.objects.get(user=shared_file.sender)
    sender_public_key = serialization.load_pem_public_key(
        sender_profile.ecdsa_public_key,
    )
    try:
        sender_public_key.verify(
            shared_file.signature,
            encrypted_data,
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        return JsonResponse({'error': 'Signature verification failed'}, status=400)
    # Decrypt the file using AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Return the decrypted file
    response = HttpResponse(decrypted_data, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{shared_file.original_filename}"'
    return response

from django.shortcuts import redirect
from django.contrib.auth import logout

def user_logout(request):
    logout(request)
    return redirect('user_login')  # or 'login' if that's your login URL name



from django.template.loader import render_to_string
from django.http import JsonResponse

@login_required
def refresh_files(request):
    shared_files = SharedFile.objects.filter(receiver=request.user).order_by('-created_at')
    sent_files = SharedFile.objects.filter(sender=request.user).order_by('-created_at')
    received_html = render_to_string('partials/received_files.html', {'shared_files': shared_files})
    sent_html = render_to_string('partials/sent_files.html', {'sent_files': sent_files})
    return JsonResponse({
        'received_files_html': received_html,
        'sent_files_html': sent_html
    })


from django.contrib.auth import logout
from django.shortcuts import redirect

def user_logout(request):
    logout(request)
    return redirect('login')  # Use 'login' if that's your login URL name


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import Message
from django.db.models import Q
from datetime import datetime
from django.utils.timezone import make_aware

@login_required
def chat_room(request, room_name):
    search_query = request.GET.get('search', '') 
    users = User.objects.exclude(id=request.user.id) 
    chats = Message.objects.filter(
        (Q(sender=request.user) & Q(receiver__username=room_name)) |
        (Q(receiver=request.user) & Q(sender__username=room_name))
    )

    if search_query:
        chats = chats.filter(Q(content__icontains=search_query))  

    chats = chats.order_by('timestamp') 
    user_last_messages = []

    for user in users:
        last_message = Message.objects.filter(
            (Q(sender=request.user) & Q(receiver=user)) |
            (Q(receiver=request.user) & Q(sender=user))
        ).order_by('-timestamp').first()

        user_last_messages.append({
            'user': user,
            'last_message': last_message
        })

    # Sort user_last_messages by the timestamp of the last_message in descending order
    user_last_messages.sort(
         key=lambda x: x['last_message'].timestamp if x['last_message'] else make_aware(datetime.min),
        reverse=True
    )

    return render(request, 'chat.html', {
        'room_name': room_name,
        'chats': chats,
        'users': users,
        'user_last_messages': user_last_messages,
        'search_query': search_query 
    })




def generate_otp():
    """Generate a 6-digit OTP."""

    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(request):
    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)  # Check if user exists
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=400)

        otp = random.randint(100000, 999999)  # Generate a 6-digit OTP

        # Store OTP in session
        request.session['otp'] = otp
        request.session['email'] = email

        # Send OTP via Email
        send_mail(
            "Your OTP Code",
            f"Your OTP is: {otp}. It is valid for 5 minutes.",
            "securechat00@gmail.com",  # Replace with your email
            [email],
            fail_silently=False,
        )

        return JsonResponse({'message': 'OTP sent to your email!'})
    
    return JsonResponse({'error': 'Invalid request'}, status=400)




from django.core.mail import send_mail
from django.http import JsonResponse
from django.contrib.auth import authenticate
import random
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def send_otp(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            return JsonResponse({"success": False, "message": "Username and password are required."}, status=400)

        user = authenticate(request, username=username, password=password)
        if user is not None:
            otp = str(random.randint(100000, 999999))  # Generate OTP
            request.session["otp"] = otp  # Store OTP in session
            request.session["otp_user"] = user.id  # Store user ID

            try:
                send_mail(
                    "Your OTP Code",
                    f"Your OTP is: {otp}",
                    "your_email@gmail.com",
                    [user.email],
                    fail_silently=False,
                )
                return JsonResponse({"success": True, "message": "OTP sent to your email."})
            except Exception as e:
                return JsonResponse({"success": False, "message": f"Email failed: {str(e)}"}, status=500)

        return JsonResponse({"success": False, "message": "Invalid username or password."}, status=401)

    return JsonResponse({"success": False, "message": "Invalid request."}, status=400)


def verify_otp(request):
    if request.method == "POST":
        entered_otp = request.POST.get("otp")
        stored_otp = request.session.get("otp")
        user_id = request.session.get("otp_user")

        if entered_otp == stored_otp and user_id:
            # Log in the user
            from django.contrib.auth.models import User
            user = User.objects.get(id=user_id)
            login(request, user)

            # Clear OTP from session
            del request.session["otp"]
            del request.session["otp_user"]

            return JsonResponse({"success": True, "message": "OTP verified. Logging in..."})
        else:
            return JsonResponse({"success": False, "message": "Invalid OTP."})

    return JsonResponse({"success": False, "message": "Invalid request."})


import cv2
import os
import numpy as np
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings

DATASET_PATH = os.path.join(settings.BASE_DIR, 'dataset')
MODEL_PATH = os.path.join(settings.BASE_DIR, 'trainer.yml')
LABELS_PATH = os.path.join(settings.BASE_DIR, 'labels.npy')

import base64
from PIL import Image
from io import BytesIO

def register_face_view(request):
    if request.method == 'POST':
        username = request.session.get('username')
        image_data = request.POST['captured_image']

        if not username or not image_data:
            return HttpResponse("Missing data")

        user_folder = os.path.join(DATASET_PATH, username)
        os.makedirs(user_folder, exist_ok=True)

        image_data = image_data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        image = Image.open(BytesIO(image_bytes)).convert('L')
        image.save(os.path.join(user_folder, '1.jpg'))

        train_model()
        return redirect('login')  # send back to login page

    return render(request, 'face_register.html')


def train_model():
    recognizer = cv2.face.LBPHFaceRecognizer_create()
    faces, labels = [], []
    label_dict = {}
    label_id = 0

    for user in os.listdir(DATASET_PATH):
        user_path = os.path.join(DATASET_PATH, user)
        if not os.path.isdir(user_path): continue
        if user not in label_dict:
            label_dict[user] = label_id
            label_id += 1
        for image in os.listdir(user_path):
            img_path = os.path.join(user_path, image)
            img = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)
            faces.append(img)
            labels.append(label_dict[user])

    recognizer.train(faces, np.array(labels))
    recognizer.save(MODEL_PATH)
    with open(LABELS_PATH, 'wb') as f:
        np.save(f, label_dict)



def login_face_view(request):
    if request.method == 'POST':
        username = request.session.get('username')
        image_data = request.POST['captured_image']

        if not username or not image_data:
            return HttpResponse("Missing data")

        image_data = image_data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        image = Image.open(BytesIO(image_bytes)).convert('L')
        image_np = np.array(image)

        recognizer = cv2.face.LBPHFaceRecognizer_create()
        recognizer.read(MODEL_PATH)
        with open(LABELS_PATH, 'rb') as f:
            label_dict = np.load(f, allow_pickle=True).item()

        if username not in label_dict:
            return HttpResponse("User not registered")

        label, confidence = recognizer.predict(image_np)
        predicted_user = list(label_dict.keys())[list(label_dict.values()).index(label)]

        if predicted_user == username and confidence < 70:
            return redirect('home')
        else:
            return HttpResponse("Face not recognized")

    return render(request, 'face_login.html')


