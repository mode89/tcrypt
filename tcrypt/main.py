from argparse import ArgumentParser
import base64
from getpass import getpass
import os
from select import select
import subprocess
import sys
import tempfile
import zlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
BIN_VERSION = 2

def main():
    args = parse_arguments()
    input_text = input() if has_some_input() else ""
    if input_text:
        password = getpass()
        text = decrypt(password, input_text)
        if args.edit:
            new_text = edit(text)
            new_data = encrypt(password, new_text)
            print_encrypted(new_data)
        else:
            print(text)
    else:
        text = edit("")
        if text:
            password = getpass()
            data = encrypt(password, text)
            print_encrypted(data)

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
    data_to_encrypt = zlib.compress(text.encode("utf-8"), level=9)
    salt = os.urandom(SALT_SIZE)
    f = make_fernet(password, salt)
    token = f.encrypt(data_to_encrypt)
    return f"{BIN_VERSION:02}" + \
        base64.b32encode(salt + token).decode("utf-8")

def decrypt(password, text):
    try:
        version = int(text[:2])
    except:
        raise RuntimeError("Failed to parse binary version")
    f = globals().get(f"decrypt_{version}")
    assert f, f"Unsupported binary version: {version}"
    return f(password, text)

def decrypt_1(password, text):
    decoded = base64.b32decode(text[2:].encode("utf-8"))
    salt = decoded[:SALT_SIZE]
    assert len(salt) == SALT_SIZE, "Not enough salt"
    token = decoded[SALT_SIZE:]
    f = make_fernet(password, salt)
    return f.decrypt(token).decode("utf-8")

def decrypt_2(password, text):
    decoded = base64.b32decode(text[2:].encode("utf-8"))
    salt = decoded[:SALT_SIZE]
    assert len(salt) == SALT_SIZE, "Not enough salt"
    token = decoded[SALT_SIZE:]
    f = make_fernet(password, salt)
    decrypted = f.decrypt(token)
    return zlib.decompress(decrypted).decode("utf-8")

def make_fernet(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)

def edit(text):
    assert isinstance(text, str)
    editor = os.environ.get("EDITOR")
    assert editor, "EDITOR environment variable is not set"
    try:
        temp_file, temp_file_path = tempfile.mkstemp(dir="/dev/shm")
        os.write(temp_file, text.encode("utf-8"))
        os.close(temp_file)
        subprocess.run([editor, temp_file_path], check=True)
        with open(temp_file_path, "r") as f:
            return f.read()
    finally:
        os.remove(temp_file_path)

def print_encrypted(data):
    print(f"Encrypted: {data}")

if __name__ == "__main__":
    main()
