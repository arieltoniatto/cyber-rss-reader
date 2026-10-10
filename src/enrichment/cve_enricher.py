from dataclasses import replace
from cti.cve import article_cves
from parser.models import Article


class CVEEnricher:
    """Persist compact CVE references; public records resolve through a separate cache."""
    @property
    def name(self):
        return 'cve'

    async def enrich(self, article: Article) -> Article:
        return replace(article, cve_ids=article_cves(article))
