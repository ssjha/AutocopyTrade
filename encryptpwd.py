import base64
import os
import dotenv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
# for firsttime you can generate using 
#mysecret = Fernet.generate_key()
#print (mysecret)
#
# salt = os.urandom(16)  
#kdf = PBKDF2HMAC(
#    algorithm=hashes.SHA256(),
#    length=32,
#    salt=salt,
#    iterations=100000,
#    backend=default_backend()
#)
#key = base64.urlsafe_b64encode(kdf.derive(mysecret)) 

dotenv.load()
if (dotenv.get('key')):
    mysecret = dotenv.get('key').encode()
else:
    mysecret = Fernet.generate_key()
    with open(".env", "w") as envf:
        envf.write("key={}".format(mysecret.decode()))
print(mysecret)
f = Fernet(mysecret)
#decrpted = f.decrypt('gAAAAABiQsGiMZZGSytxyU2If0irN9QhcAH1q2CuECw9tRDWF-rl0Im0G3yb9AohKQl6jdeBmKR45C66EjuGO-Mjb0sSMnIMFw=='.encode())
#print(decrpted.decode())
password_provided = input("enter string to encrypt : ")
password = str(password_provided).encode()  # Convert to type bytes,
encrypted = f.encrypt(password)
print (encrypted.decode())

