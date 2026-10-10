from dataclasses import replace
from cti.attack_mapping import AttackCatalog
from parser.models import Article


class AttackEnricher:
    def __init__(self, catalog: AttackCatalog | None):
        self.catalog = catalog

    @property
    def name(self):
        return 'attack'

    async def enrich(self, article: Article) -> Article:
        if self.catalog is None:
            return article
        return replace(article, attack=self.catalog.detect(article))
