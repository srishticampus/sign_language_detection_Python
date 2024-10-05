import random
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.http import StreamingHttpResponse, JsonResponse
import cv2
from .forms import CustomPasswordResetForm, UserRegistrationForm, LoginForm, CustomPasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from super_gradients.training import models
import threading
import os
import sys

stop_video = False
video_thread = None

model = models.get('yolo_nas_s', num_classes=26, checkpoint_path='model_weights/ckpt_best.pth')


def generate_otp():
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))


def send_otp_via_email(user, otp):
    """Send OTP to user's email for password reset."""
    subject = "Your OTP for Password Reset"
    message = f"Your OTP for password reset is {otp}. Use this to reset your password."
    send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])


def register_view(request):
    """Handle user registration."""
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Registration successful. Please login.')
            return redirect('login')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserRegistrationForm()
    storage = messages.get_messages(request)
    storage.used = True
    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    """Handle user login."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Login successful.')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            for error in form.errors.values():
                messages.error(request, error)
    else:
        form = LoginForm()
    storage = messages.get_messages(request)
    storage.used = True
    return render(request, 'accounts/login.html', {'form': form})


@login_required
def dashboard_view(request):
    """User dashboard view."""
    return render(request, 'accounts/dashboard.html')


def logout_view(request):
    """Handle user logout."""
    logout(request)
    return redirect('login')


def password_reset_email_view(request):
    """Handle the password reset form submission."""
    if request.method == 'POST':
        form = CustomPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            messages.success(request, f'Password reset instructions have been sent to {email}.')
            return redirect('verify_otp')
        else:
            for error in form.errors.values():
                messages.error(request, error)
    else:
        form = CustomPasswordResetForm()
    return render(request, 'accounts/password_reset_email.html', {'form': form})


def verify_otp_view(request):
    """View for OTP verification during password reset."""
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        if entered_otp == request.session.get('otp'):
            return redirect('password_reset_confirm')
        else:
            messages.error(request, 'Invalid OTP.')
    return render(request, 'accounts/verify_otp.html')


def password_reset_confirm_view(request):
    """View for resetting the password after OTP verification."""
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if password == confirm_password:
            email = request.session.get('email')
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successful. Please log in.')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match.')
    return render(request, 'accounts/password_reset_confirm.html')


def instruction_view(request):
    """View for rendering instructions."""
    return render(request, 'accounts/instruction.html')

def     blog_view(request):
    """show the blogs."""
    return render(request, 'accounts/blogs.html')

@login_required(login_url='login')
def test_view(request):
    """View for testing the sign language detector."""
    return render(request, 'accounts/test.html')


@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST) 
        if form.is_valid():
            user = form.save()  
            update_session_auth_hash(request, user)  
            messages.success(request, 'Your password has been successfully changed.')
            return redirect('dashboard')  
        else:
            for error in form.errors.values():
                messages.error(request, error)
    else:
        form = CustomPasswordChangeForm(user=request.user)  
    storage = messages.get_messages(request)
    storage.used = True
    return render(request, 'accounts/change_password.html', {'form': form})



stop_video = False
video_thread = None

def predict_sign(frame):
    """Function to predict sign language gesture from a video frame using the YOLO model."""
    result = model.predict_webcam()
    predicted_sign = result[0]["class"] if result else "None"
    return predicted_sign

def gen_frames():
    """Capture webcam feed and yield video frames with predicted sign overlaid."""
    global stop_video
    cap = cv2.VideoCapture(0)  
    try:
        while True:
            if stop_video:
                break
            success, frame = cap.read()
            if not success:
                break
            else:
                sign_prediction = predict_sign(frame)
                cv2.putText(frame, f'Detected Sign: {sign_prediction}', (50, 50), 
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2, cv2.LINE_AA)
                ret, buffer = cv2.imencode('.jpg', frame)
                frame = buffer.tobytes()

                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    finally:
        cap.release()

def video_feed(request):
    """Video feed view for the sign language detection."""
    global stop_video, video_thread
    stop_video = False 

    if video_thread is None or not video_thread.is_alive():
        video_thread = threading.Thread(target=gen_frames)
        video_thread.start()

    return StreamingHttpResponse(gen_frames(), content_type='multipart/x-mixed-replace; boundary=frame')

def stop_video_feed(request):
    """Stop the video feed."""
    global stop_video, video_thread
    stop_video = True 

    if video_thread is not None:
        video_thread.join()
        video_thread = None

    return JsonResponse({'status': 'stopped'})


def restart_server():
    """Function to restart the Django development server."""
    try:
        os.execv(sys.executable, ['python'] + sys.argv)
    except Exception as e:
        print(f"Error restarting the server: {e}")


def stop_and_restart_view(request):
    """View to stop video stream and restart the server."""
    global stop_video
    stop_video = True

    
    threading.Thread(target=restart_server).start()

    return JsonResponse({'status': 'restarting'})
