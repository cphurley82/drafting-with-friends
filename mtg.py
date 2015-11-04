import os
import json
import collections
import random

class SetUtil:
    @classmethod
    def __init__(cls):
        all_set_data_file_path = os.path.join(os.path.dirname(__file__), 
            'm12_only.json')
        with open(all_set_data_file_path) as all_sets_file:
            cls.sets = json.load(all_sets_file)

    @classmethod
    def generate_booster(cls, set_code):
        cards = []
        rarity_counts = collections.Counter()
        # print(str(cls.sets.keys()))
        for booster_slot in cls.sets[set_code]['booster']:
            # print('booster_slot='+str(booster_slot))
            if isinstance(booster_slot, basestring): #it is a rarity name
                if(booster_slot == 'mythic' or booster_slot == 'rare' 
                   or booster_slot == 'uncommon' or booster_slot == 'common'):
                    rarity_counts[booster_slot] += 1
            else: #it is a list of rarities like rare or mythic rare
                #TODO: fix mythic/rare selection
                for i in range(8):
                    booster_slot.append('rare')
                rarity_counts[random.choice(booster_slot)] += 1

        for rarity, count in rarity_counts.iteritems():
            cards += random.sample(cls.get_cards(set_code=set_code, 
                rarity=rarity), count) 
        return cards

    @classmethod
    def generate_boosters(cls, num, set_code):
        boosters = []
        for i in range(num):
            boosters.append(cls.generate_booster(set_code=set_code))
        return boosters

    #returns None if it can't find a card matching the criteria
    #assuming random selection for now
    @classmethod
    def get_cards(cls, set_code, rarity):
        cards = []
        for card in cls.sets[set_code]['cards']:
            if card['rarity'].lower() == rarity:
                cards.append(card['name'])
        return cards

    @classmethod
    def data(cls):
        return cls.sets

# class MtgCardUtil:
#     def __init__(self):
#         all_cards_data_file_path = os.path.join(os.path.dirname(__file__), 
#             'AllCards-x.json')
#         with open(all_cards_data_file_path) as all_cards_file:
#             self.cards = json.load(all_cards_file)

setutil = SetUtil()

import unittest
class TestSetUtil(unittest.TestCase):

    def setUp(self):
        self.setutil = SetUtil()

    def test_get_cars_by_rarity(self):
        mythics = self.setutil.get_cards(set_code='M13', rarity='mythic rare')
        print("The M13 mythics are:")
        print(mythics)

    def test_m13_booster_generation(self):
        cards = self.setutil.generate_booster('M13')
        print('M13 pack:')
        for card in cards:
            print(card)


if __name__ == '__main__':
    unittest.main()
