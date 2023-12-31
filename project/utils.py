from .config import PASSWORD_POLICY, PASSWORD_BLACKLIST
from flask import Request

def is_bot(request: Request) -> bool:
    resp = get_recaptcha_response(request)
    return not resp['success']
    
def get_recaptcha_response(request: Request):
    import requests
    from . import env 
    recaptcha_response = request.form.get('g-recaptcha-response')

    data = {
        'secret': env['RECAPTCHA_PRIVATE_KEY'],
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    return response.json()

def password_meets_security_requirements(password: str) -> bool:
    nonalpha = "'-!\"£#$%&()*,./:;?@[]^_`{|}~+<=>"
    nums = "0123456789"
    lowerchars = "abcdefghijklmnopqrstuvwxyz"
    upperchars = lowerchars.upper()

    no_of_alpha_chars = len(list(filter(lambda c: c in nonalpha, password)))
    no_of_upper_chars = len(list(filter(lambda c: c in upperchars, password)))
    no_of_lower_chars = len(list(filter(lambda c: c in lowerchars, password)))
    no_of_numeric_chars = len(list(filter(lambda c: c in nums, password)))
    password_too_common = password in PASSWORD_BLACKLIST

    return (
        no_of_alpha_chars >= PASSWORD_POLICY["MIN_NO_OF_ALPHA_CHARS"]
        and no_of_upper_chars >= PASSWORD_POLICY["MIN_NO_OF_UPPERCASE_CHARS"]
        and no_of_lower_chars >= PASSWORD_POLICY["MIN_NO_OF_LOWERCASE_CHARS"]
        and no_of_numeric_chars >= PASSWORD_POLICY["MIN_NO_OF_NUMERIC_CHARS"]
        and len(password) >= PASSWORD_POLICY["MINIMUM_LENGTH"]
        and not password_too_common
    )


def file_signature_valid(extension: str, file: bytes) -> bool:
    """
    Check a file is what it says it is. 
    
    Compares the `.extension` parameter against that file types' known file 
    header.

    List of valid extensions: 
    png, 
    apng*
    avif, 
    gif, 
    webp,
    jpg,
    jpeg,
    jfif*
    pjpeg*
    pjp*

    Extensions with an asterisk are not supported, but will match the pattern in the 
    event of extension spoofing 
    """
    if extension == "png" or extension == "apng":
        return file[:8] == bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    elif extension == "avif":
        return file[:18] == bytes(
            [
                0x00,
                0x00,
                0x00,
                0x20,
                0x66,
                0x74,
                0x79,
                0x70,
                0x61,
                0x76,
                0x69,
                0x66,
                0x31,
                0x61,
                0x76,
                0x69,
                0x66,
                0x31,
            ]
        )
    elif extension == "gif":
        return file[:6] == bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]) or file[
            :6
        ] == bytes([0x47, 0x49, 0x46, 0x38, 0x37, 0x61])
    elif extension == "webp":
        return file[:4] == bytes([0x52, 0x49, 0x46, 0x46]) and file[8:12] == bytes(
            [0x57, 0x45, 0x42, 0x50]
        )
    elif extension in ["jpg", "jpeg", "jfif", "pjpeg", "pjp"]:
        return (
            file[:4] == bytes([0xFF, 0xD8, 0xFF, 0xDB])
            or file[:12]
            == bytes(
                [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01]
            )
            or file[:4] == bytes([0xFF, 0xD8, 0xFF, 0xEE])
            or (
                file[:4] == bytes([0xFF, 0xD8, 0xFF, 0xE1])
                and file[6:12] == bytes([0x45, 0x78, 0x69, 0x66, 0x00, 0x00])
            )
        )
    elif extension == "webp":
        return (
            file[:4] == bytes([0x52, 0x49, 0x46, 0x46]) and 
            file[8:12] == bytes([0x57, 0x45, 0x42, 0x50]) 
        )

    return True
