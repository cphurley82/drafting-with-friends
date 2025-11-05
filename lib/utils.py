'''
Created on Nov 17, 2015

@author: cphurley
'''

import hmac
import hashlib
import os

from passlib.hash import bcrypt

#### authentication stuff
SECRET = os.environ.get('DWF_COOKIE_SECRET', 'change-me-please')


def make_secure_val(val):
    value = val.encode('utf-8') if isinstance(val, str) else val
    digest = hmac.new(SECRET.encode('utf-8'), value, hashlib.sha256).hexdigest()
    if isinstance(val, bytes):
        val = val.decode('utf-8')
    return f'{val}|{digest}'


def check_secure_val(secure_val):
    if not secure_val:
        return None
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
    return None


##### user stuff
def make_pw_hash(name, password):
    return bcrypt.hash(f'{name}{password}')


def valid_pw(name, password, hashed):
    try:
        return bcrypt.verify(f'{name}{password}', hashed)
    except ValueError:
        return False