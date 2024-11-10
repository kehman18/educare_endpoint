import os
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from core.config import get_settings

settings = get_settings()

def send_verification_email(recipient_email: str, verification_token: str):
    # Email configuration
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER')
    smtp_password = os.getenv('SMTP_PASSWORD')
    
    sender_email = smtp_user
    subject = "Email Verification for Your Account"
    verification_url = f"{os.getenv('FRONTEND_URL')}/verify-email?token={verification_token}"
    html_content = f"""
    <html>
    <body>
        <p>Hello,</p>
        <p>Thank you for registering. Please verify your email by clicking the link below:</p>
        <a href="{verification_url}">Verify Your Email</a>
        <p>If you did not register, please ignore this email.</p>
    </body>
    </html>
    """

    # Create the email message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(html_content, "html"))

    # Send the email
    try:
        with SMTP(smtp_server, smtp_port) as smtp:
            smtp.starttls()  # Enable TLS
            smtp.login(smtp_user, smtp_password)
            smtp.sendmail(sender_email, recipient_email, message.as_string())
        print(f"Verification email sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send verification email to {recipient_email}: {e}")
