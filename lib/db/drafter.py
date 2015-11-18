'''
Created on Nov 17, 2015

@author: cphurley
'''

from google.appengine.ext import ndb

class Drafter(ndb.Model):
    '''
    classdocs
    '''
    
    user_key = ndb.KeyProperty(required = True)
    draft_key = ndb.KeyProperty(required = True)
    position = ndb.IntegerProperty(required = True)

    pack_keys = ndb.KeyProperty(repeated = True)
    picked_cards = ndb.StringProperty(repeated = True)
    
    num_picks_made = ndb.ComputedProperty(lambda self: len(self.picked_cards))
    num_picks_queued = ndb.ComputedProperty(lambda self: len(self.pack_keys))

    @classmethod
    def create(cls, user_key, draft_key, position):
        return Drafter(user_key = user_key,
                       draft_key = draft_key,
                       position = position)

    def get_num_packs_queued(self):
        return len(self.pack_keys)