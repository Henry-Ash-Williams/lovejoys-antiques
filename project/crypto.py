from cryptography.fernet import Fernet
from . import env
import base64 

cipher = Fernet(env['IMAGE_KEY'])