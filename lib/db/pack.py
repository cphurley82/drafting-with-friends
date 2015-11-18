'''
Created on Nov 17, 2015

@author: cphurley
'''

from google.appengine.ext import ndb

class Pack(ndb.Model):    
    '''
    classdocs
    '''

    draft_key = ndb.KeyProperty(required=True)
    cards = ndb.StringProperty(repeated=True)

    @classmethod
    def create(cls, draft_key, cards=[]):
        return Pack(draft_key=draft_key, 
                    cards=cards)
