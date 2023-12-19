from datetime import timedelta

PASSWORD_RESET_TIMEOUT = timedelta(minutes=30.0)

# PASSWORD_POLICY = {
#     # Minimum number of characters in a password
#     'MINIMUM_LENGTH': 16,

#     # Minimum number of alphanumeric characters
#     # i.e. "'-!"£#$%&()*,./:;?@[]^_`{|}~+<=>"
#     'MIN_NO_OF_ALPHA_CHARS': 2,

#     # Minimum number of uppercase characters
#     'MIN_NO_OF_UPPERCASE_CHARS': 2,

#     # Minimum number of lowercase characters
#     'MIN_NO_OF_LOWERCASE_CHARS': 2,

#     # Minimum number of numeric characters
#     'MIN_NO_OF_NUMERIC_CHARS': 2,
# }

PASSWORD_POLICY = {
    # Minimum number of characters in a password
    'MINIMUM_LENGTH': 0,

    # Minimum number of alphanumeric characters
    # i.e. "'-!"£#$%&()*,./:;?@[]^_`{|}~+<=>"
    'MIN_NO_OF_ALPHA_CHARS': 0,

    # Minimum number of uppercase characters
    'MIN_NO_OF_UPPERCASE_CHARS': 0,

    # Minimum number of lowercase characters
    'MIN_NO_OF_LOWERCASE_CHARS': 0,

    # Minimum number of numeric characters
    'MIN_NO_OF_NUMERIC_CHARS': 0,
}

ALLOWED_FILETYPES = [
    "apng",
    "avif",
    "gif",
    "jpg",
    "jpeg",
    "jfif",
    "pjpeg",
    "pjp",
    "png",
    "webp",
]
