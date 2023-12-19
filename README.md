# Lovejoys Antiques 

## Install 

```sh
$ git clone git@github.com:Henry-Ash-Williams/lovejoys-antiques
$ cd lovejoys-antiques
$ pip install -r requirements.txt
```

## Requirements 

### `.env`

The `.env` file contains a set of environment variables which contain sensitive information such as API keys, and encryption keys. In order for this project to work, it requires the following variables to be set 

- `SECURITY_PASSWORD_SALT`: Used by `itsdangerous` as part of the email verification step 
- `RESEND_API_KEY`: API key used to interact with [resend](https://resend.com/overview), used to send emails 
- `RECAPTCHA_PUBLIC_KEY`: The site key provided by google recaptcha 
- `RECAPTCHA_PRIVATE_KEY`: The secret key provided by google recaptcha 
- `IMAGE_KEY`: The key used to encrypt and decrypt images 
