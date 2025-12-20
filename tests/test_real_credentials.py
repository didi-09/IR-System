
import smtplib
from email.mime.text import MIMEText

def test_gmail_auth():
    sender = "abdelrahamanzakaria@gmail.com"
    password = "DiDi/311"
    
    print(f"🔒 Attempting to authenticate with {sender}...")
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        print("✅ SUCCESS: Password accepted!")
        server.quit()
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ FAILURE: Google rejected the password.")
        print(f"   Reason: {e}")
    except Exception as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    test_gmail_auth()
