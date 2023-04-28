import base64
from getpass import getpass
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PASSWORD = "password"
TEXT = "Hello, 42!"
ENCODED = "HWYOUF2IG2L76KAOFRHQOO2GBZTUCQKBIFAUE22TG5YDMM3XM5WTMQ3" + \
    "VPFBE2ZSRM42DAOKQNE2FIQTEKRLTAZRVJJLWM6KYKVFEWQLQNBLDMSBZPFMV" + \
    "M33DPFIEYNKDMRBHM6KFMFNDO2CIIZVXM23UOJGUE6TSJYZHQWLNGRQTOSDDM" + \
    "F3XMZZ5HU======"
SALT_SIZE = 16

def main():
    encoded_text = input()
    password = getpass()
    text = decrypt(password, encoded_text)
    print(text)

def encrypt(password, text):
    salt = os.urandom(SALT_SIZE)
    f = make_fernet(password, salt)
    token = f.encrypt(text.encode("utf-8"))
    return base64.b32encode(salt + token).decode("utf-8")

def decrypt(password, text):
    decoded = base64.b32decode(text.encode("utf-8"))
    salt = decoded[:SALT_SIZE]
    assert len(salt) == SALT_SIZE, "Not enough salt"
    token = decoded[SALT_SIZE:]
    f = make_fernet(password, salt)
    return f.decrypt(token).decode("utf-8")

def make_fernet(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)

if __name__ == "__main__":
    main()
