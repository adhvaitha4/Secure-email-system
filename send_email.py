import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_email(sender_email, recipient_email, subject, body, password):
    msg = MIMEMultipart()  # Create a MIMEMultipart message object
    msg['From'] = sender_email  # Set the sender's email address
    msg['To'] = recipient_email  # Set the recipient's email address
    msg['Subject'] = subject  # Set the email subject
    msg.attach(MIMEText(body, 'plain'))  # Attach the body content as plain text

    try:
        # Connect to Gmail’s SMTP server with SSL encryption (port 465)
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, password)  # Log in to your Gmail account
        text = msg.as_string()  # Convert the message to a string
        server.sendmail(sender_email, recipient_email, text)  # Send the email
        print("Email sent successfully!")  # Print success message
    except Exception as e:
        print(f"Failed to send email: {e}")  # Print error message if sending fails
    finally:
        server.quit()  # Close the connection to the server


send_email(
    sender_email='adhvaitha102@gmail.com',
    recipient_email='adhvaitha4@example.com',
    subject='Test Email',
    body='Hello, this is a test email!',
    password='send_email(
    sender_email='youremail@gmail.com',
    recipient_email='recipientemail@example.com',
    subject='Test Email',
    body='Hello, this is a test email!',
    password='quds ufnh mowr jlpm'
)
'
)
