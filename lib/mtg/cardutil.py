'''
Created on Nov 17, 2015

@author: chris
'''
import os
import json

class CardUtil(object):
    '''
    classdocs
    '''
    @classmethod
    def __init__(cls):
        '''
        Constructor
        '''
        all_cards_data_file_path = os.path.join(os.path.dirname(__file__), 
            'AllCards.json')
        with open(all_cards_data_file_path) as all_cards_file:
            cls.cards = json.load(all_cards_file)

    @classmethod
    def data(cls):
        return cls.cards
        