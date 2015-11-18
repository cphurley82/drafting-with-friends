'''
Created on Nov 17, 2015

@author: cphurley
'''
from google.appengine.ext import ndb
from lib.utils import make_pw_hash, valid_pw

def users_key(group = 'default'):
    return ndb.Key('users', group)

class User(ndb.Model):
    '''
    classdocs
    '''
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()
    friends = ndb.KeyProperty(repeated = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.query(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u