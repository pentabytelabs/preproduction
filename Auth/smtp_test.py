# save as smtp_test.py and run with the same python you use for Flask
import smtplib
from smtplib import SMTPAuthenticationError

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
USERNAME = "rpimailservermegaanon@gmail.com"
APP_PASSWORD = "mxbkmlmirrbvfqxk"  # <<-- set here

try:
    s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
    s.ehlo()
    s.starttls()
    s.ehlo()
    s.login(USERNAME, APP_PASSWORD)
    print("✅ SMTP login successful")
    s.quit()
except SMTPAuthenticationError as e:
    print("❌ SMTPAuthenticationError:", e)
except Exception as e:
    print("❌ Other exception:", e)
