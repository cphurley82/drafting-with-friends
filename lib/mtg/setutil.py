import json
import random
from collections import Counter
from pathlib import Path
from typing import Dict, List


class SetUtil:
    def __init__(self):
        self.sets = self._load_sets()

    def _load_sets(self) -> Dict[str, dict]:
        sets = {}
        data_dir = Path(__file__).parent / "set_data"
        for json_path in data_dir.glob("*.json"):
            with json_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            code = data.get("code") or json_path.stem.upper()
            data.setdefault("name", code)
            sets[code] = data
        return sets

    def generate_booster(self, set_code: str) -> List[str]:
        data = self.sets.get(set_code)
        if not data:
            raise KeyError(f"Unknown set code: {set_code}")

        rarity_counts = Counter()
        booster_slots = data.get("booster", [])
        for slot in booster_slots:
            if isinstance(slot, str):
                rarity_counts[slot.lower()] += 1
            elif isinstance(slot, list):
                options = [option.lower() for option in slot]
                rarity_counts[random.choice(options)] += 1

        cards = []
        for rarity, count in rarity_counts.items():
            available = self.get_cards(set_code=set_code, rarity=rarity)
            if len(available) < count:
                raise ValueError(
                    f"Not enough cards of rarity '{rarity}' for set '{set_code}'"
                )
            cards.extend(random.sample(available, count))

        if not cards and data.get("cards"):
            # fallback to any card if no rarity information is provided
            cards = random.sample([card["name"] for card in data["cards"]], k=min(15, len(data["cards"])) )

        return cards

    def generate_boosters(self, num: int, set_code: str) -> List[List[str]]:
        return [self.generate_booster(set_code) for _ in range(num)]

    def get_cards(self, set_code: str, rarity: str) -> List[str]:
        rarity = rarity.lower()
        cards = []
        for card in self.sets[set_code].get("cards", []):
            if card.get("rarity", "").lower() == rarity:
                cards.append(card["name"])
        if not cards and rarity in {"cube", "any"}:
            cards = [card["name"] for card in self.sets[set_code].get("cards", [])]
        return cards

    def data(self) -> Dict[str, dict]:
        return self.sets

    def get_card_details(self, set_code: str, card_name: str) -> dict:
        data = self.sets.get(set_code, {})
        for card in data.get("cards", []):
            if card.get("name") == card_name:
                return card
        return {"name": card_name}

import unittest
class TestSetUtil(unittest.TestCase):

    def setUp(self):
        self.setutil = SetUtil()

    def test_get_cards_by_rarity(self):
        cards = self.setutil.get_cards(set_code='VCUBE', rarity='cube')
        self.assertTrue(cards)

    def test_vcube_booster_generation(self):
        cards = self.setutil.generate_booster('VCUBE')
        self.assertEqual(len(cards), 15)


if __name__ == '__main__':
    unittest.main()
