import os, time, tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import pyotp, qrcode, pyAesCrypt

# ─────────────  CONFIG  ─────────────
BUFFER_SIZE = 64 * 1024
ICON_PATH   = "lock_icon.ico"          # optional .ico
QR_FILE     = "2fa_qr.png"
# ────────────────────────────────────

# 1) 2-FA secret
if not os.path.exists("secret.key"):
    secret = pyotp.random_base32(); open("secret.key","w").write(secret)
else:
    secret = open("secret.key").read().strip()

# 2) QR code on disk
if not os.path.exists(QR_FILE):
    uri = pyotp.TOTP(secret).provisioning_uri("FolderLockApp", issuer_name="Secure Locker")
    qrcode.make(uri).save(QR_FILE)

# ───────────  CORE ACTIONS  ───────────
def encrypt_folder():
    folder = filedialog.askdirectory(title="Select Folder to Encrypt")
    pwd    = simpledialog.askstring("Password","Set encryption password:",show="*")
    if not folder or not pwd: return
    enc=[];  
    for r,_,fs in os.walk(folder):
        for f in fs:
            p=os.path.join(r,f)
            if not p.endswith(".aes"):
                pyAesCrypt.encryptFile(p,p+".aes",pwd,BUFFER_SIZE); os.remove(p)
                enc.append(os.path.relpath(p+".aes",folder))
    # remove perms + hide
    os.system(f'icacls "{folder}" /inheritance:r')
    os.system(f'icacls "{folder}" /remove:g SYSTEM Administrators Users Everyone')
    os.system(f'attrib +h "{folder}"')
    for rel in enc: os.system(f'attrib +h "{os.path.join(folder,rel)}"')
    messagebox.showinfo("Done", "Encrypted & hidden:\n"+("\n".join(enc) if enc else "No files."))

def decrypt_folder():
    folder = filedialog.askdirectory(title="Select Folder to Decrypt")
    pwd    = simpledialog.askstring("Password","Enter decryption password:",show="*")
    if not folder or not pwd: return
    otp    = simpledialog.askstring("2-FA","OTP from Google Authenticator:")
    if not otp or not pyotp.TOTP(secret).verify(otp):
        messagebox.showerror("Error","Invalid OTP."); return
    # restore perms + unhide
    os.system(f'takeown /f "{folder}" /r /d y')
    os.system(f'icacls "{folder}" /grant %username%:F /t /c /q')
    os.system(f'icacls "{folder}" /inheritance:e'); time.sleep(1)
    os.system(f'attrib -h "{folder}"')
    for r,_,fs in os.walk(folder):
        for f in fs: os.system(f'attrib -h "{os.path.join(r,f)}"')
    dec=[]
    for r,_,fs in os.walk(folder):
        for f in fs:
            p=os.path.join(r,f)
            if p.endswith(".aes"):
                out=p[:-4]
                try: pyAesCrypt.decryptFile(p,out,pwd,BUFFER_SIZE); os.remove(p); dec.append(os.path.relpath(out,folder))
                except Exception as e: print("Failed:",e)
    messagebox.showinfo("Done", "Decrypted & visible:\n"+("\n".join(dec) if dec else "Nothing decrypted."))

# ───────────  GUI SETUP  ───────────
root = tk.Tk(); root.title("Secure Folder Locker"); root.geometry("500x560"); root.resizable(False,False)
if os.path.exists(ICON_PATH):
    try: root.iconbitmap(ICON_PATH)
    except: pass

style=ttk.Style(); style.configure("TButton",font=("Segoe UI",12),padding=6)
frm=ttk.Frame(root,padding=25); frm.pack(expand=True)

ttk.Label(frm,text="Secure Folder Locker",font=("Segoe UI",20,"bold")).pack(pady=8)
ttk.Label(frm,text="Scan with Google Authenticator").pack(pady=2)

# Load QR *after* root exists & keep global reference
qr_img  = ImageTk.PhotoImage(Image.open(QR_FILE).resize((200,200)))
qr_lbl  = tk.Label(frm,image=qr_img); qr_lbl.pack(pady=12)

ttk.Button(frm,text="Encrypt Folder",            command=encrypt_folder).pack(pady=6)
ttk.Button(frm,text="Decrypt Folder (with 2-FA)",command=decrypt_folder).pack(pady=6)

ttk.Label(frm,text="OTP refreshes every 30 s\nRun as Administrator for permission changes.",font=("Segoe UI",9)).pack(pady=16)
root.mainloop()
