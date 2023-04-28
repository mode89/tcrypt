from argparse import ArgumentParser
import base64
from getpass import getpass
import os
from select import select
import subprocess
import sys
import tempfile

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
    args = parse_arguments()
    input_text = input() if has_some_input() else ""
    if input_text:
        password = getpass()
        text = decrypt(password, input_text)
        if args.edit:
            new_text = edit(text)
            new_data = encrypt(password, new_text)
            print("Encrypted: ", new_data)
        else:
            print(text)
    else:
        text = edit("")
        if text:
            password = getpass()
            data = encrypt(password, text)
            print("Encrypted: ", data)

def parse_arguments():
    parser = ArgumentParser()
    parser.add_argument("--edit", action="store_true")
    return parser.parse_args()

def has_some_input():
    rlist, _, _ = select([sys.stdin], [], [], 0.1)
    return bool(rlist)

def encrypt(password, text):
    assert password, "Password is empty"
    assert text, "Nothing to encrypt"
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

def edit(text):
    editor = os.environ.get("EDITOR")
    assert editor, "EDITOR environment variable is not set"
    with tempfile.NamedTemporaryFile(mode="w+") as f:
        f.write(text)
        f.flush()
        subprocess.run([editor, f.name], check=True);
        f.seek(0)
        return f.read()

if __name__ == "__main__":
    main()
