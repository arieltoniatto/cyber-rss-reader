class AttackService:
    def __init__(self, search_service, catalog):
        self.search_service = search_service
        self.catalog = catalog

    def search(self, keyword: str, *, limit: int = 5):
        articles = self.search_service.search(keyword=keyword, limit=limit)
        return [(article, self.catalog.describe(article.attack or self.catalog.detect(article)) if self.catalog else {
            'status': 'unavailable', 'catalog_version': None,
            'techniques': [], 'campaigns': [], 'relationships': []}) for article in articles]
