'''
Created on Nov 17, 2015

@author: cphurley
'''

import hmac
from bcrypt import bcrypt

#### authentication stuff
secret = 'secret goes here!'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
    
##### user stuff
def make_pw_hash(name, password):
    hashed = bcrypt.hashpw(name + password, bcrypt.gensalt())
    return hashed

def valid_pw(name, password, hashed):
    return bcrypt.hashpw(name + password, hashed) == hashed