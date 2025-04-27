Secure Folder Locker
Secure Folder Locker is a Python-based GUI application that allows you to encrypt and decrypt folders with an extra layer of Two-Factor Authentication (2FA) using Google Authenticator.
It hides folders, removes inherited permissions during encryption, and restores them during decryption.

✨ Features
Folder Encryption: Encrypts all files in a folder using AES encryption.

Folder Hiding: Automatically hides the encrypted folder and its contents.

Two-Factor Authentication (2FA): Uses Google Authenticator for secure folder decryption.

Permission Management: Revokes and restores folder permissions automatically.

Simple GUI: Easy-to-use interface built with Tkinter.

📦 Installation
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/secure-folder-locker.git
cd secure-folder-locker
Install required Python packages:

bash
Copy
Edit
pip install pillow pyotp qrcode pyaescrypt
🚀 Usage
Run the application:

bash
Copy
Edit
python gui.py
On the first run:

A QR code will be generated.

Scan the QR code with Google Authenticator.

To encrypt a folder:

Click "Encrypt Folder", select a folder, and set a password.

To decrypt a folder:

Click "Decrypt Folder (with 2-FA)".

Enter the decryption password and the current OTP from Google Authenticator.

📂 Folder Structure
gui.py – Main application script.

secret.key – Stores the 2FA secret (generated automatically).

2fa_qr.png – QR code image for Google Authenticator (generated automatically).

Note:

Ensure you run the app as Administrator for proper permission handling.

OTP refreshes every 30 seconds.

🛡️ Security Notes
Encryption uses AES (Advanced Encryption Standard) with a user-defined password.

2FA adds a second layer of security to protect your sensitive data.

