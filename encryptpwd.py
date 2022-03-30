import base64
import os
import dotenv
from cryptography.fernet import Fernet
# for firsttime you can generate key and store in .env file 
dotenv.load()
if (dotenv.get('key')):
    mysecret = dotenv.get('key').encode()
else:
    mysecret = Fernet.generate_key()
    with open(".env", "w") as envf:
        envf.write("key={}".format(mysecret.decode()))
print(mysecret)
f = Fernet(mysecret)
password_provided = input("enter string to encrypt : ")
password = str(password_provided).encode()  # Convert to type bytes,
encrypted = f.encrypt(password)
print (encrypted.decode())

