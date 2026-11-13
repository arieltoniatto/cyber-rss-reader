from __future__ import annotations

import pytest

from enrichment.tag_enricher import TagEnricher
from parser.models import Article


def create_article(
    *,
    title: str,
    summary: str = "",
    tags: list[str] | None = None,
) -> Article:
    return Article(
        title=title,
        source="Test Source",
        summary=summary,
        url="https://example.com/article",
        category="news",
        author=None,
        published=None,
        tags=list(tags or []),
    )


@pytest.mark.asyncio
async def test_preserves_existing_tags() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Security update",
        tags=[
            "Microsoft",
            "Windows",
        ],
    )

    result = await enricher.enrich(article)

    assert "Microsoft" in result.tags
    assert "Windows" in result.tags


@pytest.mark.asyncio
async def test_extracts_cti_keywords() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Ransomware attack causes data breach",
        summary="The threat actor used phishing for initial access.",
    )

    result = await enricher.enrich(article)

    assert "ransomware" in result.tags
    assert "data breach" in result.tags
    assert "threat actor" in result.tags
    assert "phishing" in result.tags
    assert "initial access" in result.tags


@pytest.mark.asyncio
async def test_extracts_and_normalizes_cves() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Exploit published for cve-2026-12345",
        summary="The issue is tracked as CVE-2026-9999.",
    )

    result = await enricher.enrich(article)

    assert "CVE-2026-12345" in result.tags
    assert "CVE-2026-9999" in result.tags


@pytest.mark.asyncio
async def test_removes_duplicate_tags_case_insensitively() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Ransomware incident",
        tags=[
            "Ransomware",
            " ransomware ",
            "RANSOMWARE",
        ],
    )

    result = await enricher.enrich(article)

    ransomware_tags = [
        tag
        for tag in result.tags
        if tag.casefold() == "ransomware"
    ]

    assert ransomware_tags == ["Ransomware"]


@pytest.mark.asyncio
async def test_does_not_modify_original_article() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Ransomware incident",
        tags=[],
    )

    result = await enricher.enrich(article)

    assert article.tags == []
    assert result.tags == ["ransomware"]
    assert result is not article


@pytest.mark.asyncio
async def test_creates_a_separate_tags_list() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Ransomware incident",
        tags=["existing"],
    )

    result = await enricher.enrich(article)

    assert result.tags is not article.tags


@pytest.mark.parametrize("text", [
    # Real archive titles that used to be tagged by substring matches.
    "Adapt your capture strategy on a laptop",
    "Velociraptor CAPTCHA chapter",
    "Malwarebytes Labs weekly roundup",
    "Leaked files show up on DDoSecrets",
    "Scan for SSH keys via Webexploits",
    "Psychologically exploitative features",
    "Forward suspicious messages to reportphishing@apple.com",
    "He is apt to agree",
    "Vamos explorar novas oportunidades",
    "There were zero days of downtime",
])
def test_keywords_glued_to_other_letters_are_not_tags(text) -> None:
    assert TagEnricher().keyword_tags(text) == []


@pytest.mark.parametrize("text,expected", [
    ("APT28 and APT 41 target Europe", ["apt"]),
    ("APTs abuse cloud services", ["apt"]),
    ("Tactics that advanced persistent threats use", ["apt"]),
    ("Flaw exploited in the wild; exploitation continues", ["exploit"]),
    ("Advanced Web Attacks and Exploitations", ["exploit"]),
    ("Link%20exploited by attackers", ["exploit"]),
    ("Threat actors deploy botnets after data breaches", ["botnet", "data breach", "threat actor"]),
    ("Critical vulnerabilities fixed", ["vulnerability"]),
    ("#StopRansomware: ALPHV Blackcat", ["ransomware"]),
    ("Model inspection RCE and a 0-Day memory leak", ["remote code execution", "zero-day"]),
    ("Spear-phishing drops an info-stealer", ["infostealer", "phishing"]),
])
def test_english_variants_produce_the_canonical_tag(text, expected) -> None:
    assert TagEnricher().keyword_tags(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("Nova vulnerabilidade explorada em ataque de ransomware", ["exploit", "ransomware", "vulnerability"]),
    ("Falha de segurança explorada por atores de ameaça", ["exploit", "threat actor"]),
    ("Vazamento de dados expõe credenciais roubadas", ["credential theft", "data breach"]),
    ("Ataque de dia zero contra a cadeia de suprimentos", ["supply chain", "zero-day"]),
    ("Execução remota de código instala código malicioso", ["malware", "remote code execution"]),
    ("Ameaça persistente avançada mira o governo", ["apt"]),
    ("Negação de serviço distribuída e sequestro de dados", ["ddos", "ransomware"]),
    ("Ciberespionagem com acesso inicial por phishing", ["cyber espionage", "initial access", "phishing"]),
    # Portuguese articles also use English terms.
    ("Campanha de phishing usa infostealer e exploit zero-day", ["exploit", "infostealer", "phishing", "zero-day"]),
    ("Vulnerabilidades críticas no NIC.br; ransomware em alta", ["ransomware", "vulnerability"]),
])
def test_portuguese_text_produces_english_tags(text, expected) -> None:
    assert TagEnricher().keyword_tags(text) == expected


@pytest.mark.asyncio
async def test_custom_keywords_match_whole_words() -> None:
    enricher = TagEnricher(keywords=["wiper", "living off the land"])

    article = create_article(
        title="Wiper uses living  off the land binaries",
        summary="Unrelated: swiper app.",
    )

    result = await enricher.enrich(article)

    assert result.tags == ["living off the land", "wiper"]
    assert enricher.keyword_tags("swiper app") == []
