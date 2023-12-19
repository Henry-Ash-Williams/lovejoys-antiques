from cryptography.fernet import Fernet
from . import secret_key
import base64 

cipher = Fernet(base64.b64encode(secret_key))