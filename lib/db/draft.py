'''
Created on Nov 17, 2015

@author: cphurley
'''
from google.appengine.ext import ndb

class Draft(ndb.Model):
    '''
    classdocs
    '''
    name = ndb.StringProperty(required=True)
    coordinator_key = ndb.KeyProperty(required=True)
    user_keys = ndb.KeyProperty(repeated=True)
    drafter_keys = ndb.KeyProperty(repeated=True)
    pack_codes = ndb.StringProperty(repeated=True)
    pack_num = ndb.IntegerProperty(required=True)
    unopened_pack_keys = ndb.KeyProperty(repeated=True)
    in_setup = ndb.BooleanProperty(required=True)
    in_progress = ndb.BooleanProperty(required=True)
    is_done = ndb.BooleanProperty(required=True)
    passing_right = ndb.BooleanProperty(required=True)
    
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty(auto_now=True)


    num_drafters = ndb.ComputedProperty(lambda self: len(self.drafter_keys))
    num_unopened_packs = ndb.ComputedProperty(
        lambda self: len(self.unopened_pack_keys))
        
    @classmethod
    def create(cls, coordinator_key, name, pack_codes):
        return Draft(name = name, 
                     user_keys = [coordinator_key],
                     coordinator_key = coordinator_key,
                     pack_codes = pack_codes,
                     pack_num = 0,
                     in_setup = True,
                     in_progress = False,
                     is_done = False,
                     passing_right = False)

    def get_num_picks_queued(self):
        num_picks_queued = 0
        for drafter_key in self.drafter_keys:
            num_picks_queued += drafter_key.get().num_picks_queued
        return num_picks_queued

    def get_current_set_code(self):
        if self.pack_num > 0 and self.pack_num <= len(self.pack_codes):
            return self.pack_codes[self.pack_num-1]

    num_picks_queued = property(fget=get_num_picks_queued)