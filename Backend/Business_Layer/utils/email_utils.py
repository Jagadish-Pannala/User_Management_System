import smtplib
from email.message import EmailMessage
from ...config.env_loader import get_env_var
import random
 
 
EMAIL_USER = get_env_var("EMAIL_USER")
EMAIL_PASSWORD = get_env_var("EMAIL_PASSWORD")
EMAIL_HOST = get_env_var("EMAIL_HOST")
EMAIL_PORT = int(get_env_var("EMAIL_PORT"))
FRONTEND_URL = get_env_var("FRONTEND_URL")
 
def send_email(to_email: str, subject: str, content: str):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_USER
    msg['To'] = to_email
    msg.set_content(content)
 
    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
        smtp.starttls()
        smtp.login(EMAIL_USER, EMAIL_PASSWORD)
        smtp.send_message(msg)
 
def generate_otp(length: int = 6) -> str:
    """Generate a numeric OTP of given length."""
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])
 
def send_otp_email(to_email: str, otp: str):
    subject = "Your OTP Code"
    content = f"Your OTP code is: {otp}. It is valid for 5 minutes."
    send_email(to_email, subject, content)
def send_welcome_email(to_email: str, name: str, temp_password: str):
    subject = "Welcome to Paves Technologies"

    content = f"""
Hello {name},

Welcome to **Paves Technologies**!

Your intranet account has been successfully created.  
Please find your login details below:

----------------------------------------
**Temporary Password:** {temp_password}
----------------------------------------

🔐 **Important:**  
For security reasons, you must change your password after logging in for the first time.  
You will not be able to continue using the intranet until your password has been updated.

You can log in and reset your password here:  
{FRONTEND_URL}

If you did not expect this email or believe it was sent in error, please contact the system administrator immediately.

Best regards,  
**User Management Team**  
_Paves Technologies_
"""

    send_email(to_email, subject, content)

 
