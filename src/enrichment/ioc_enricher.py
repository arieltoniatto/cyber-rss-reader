from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import replace

from parser.models import Article, IOC, IOCType


_URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    flags=re.IGNORECASE,
)

_EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
    flags=re.IGNORECASE,
)

_IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

_IPV6_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)

_DOMAIN_PATTERN = re.compile(
    r"\b"
    r"(?:"
    r"[A-Z0-9]"
    r"(?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"\."
    r")+"
    r"[A-Z]{2,63}"
    r"\b",
    flags=re.IGNORECASE,
)

_SHA256_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"
)

_SHA1_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"
)

_MD5_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"
)

_CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    flags=re.IGNORECASE,
)

_ASN_PATTERN = re.compile(
    r"\bAS\d{1,10}\b",
    flags=re.IGNORECASE,
)

_TRAILING_URL_CHARACTERS = ".,;:!?)]}>\"'"

_NON_DOMAIN_SUFFIXES = {
    "css",
    "csv",
    "dll",
    "doc",
    "docx",
    "exe",
    "gif",
    "jpeg",
    "jpg",
    "js",
    "json",
    "log",
    "pdf",
    "png",
    "ps1",
    "py",
    "rar",
    "sh",
    "svg",
    "sys",
    "tar",
    "txt",
    "xls",
    "xlsx",
    "xml",
    "yaml",
    "yml",
    "zip",
}


class IOCEnricher:
    """
    Extracts common cyber threat intelligence observables from articles.

    The article's source URL is intentionally excluded from extraction.
    Only the title and summary are analyzed.
    """

    @property
    def name(self) -> str:
        return "ioc"

    async def enrich(self, article: Article) -> Article:
        """
        Return a new Article containing extracted IOCs.
        """
        content = self._build_searchable_content(article)

        extracted_iocs = [
            *self._extract_urls(content),
            *self._extract_emails(content),
            *self._extract_ipv4_addresses(content),
            *self._extract_ipv6_addresses(content),
            *self._extract_domains(content),
            *self._extract_sha256_hashes(content),
            *self._extract_sha1_hashes(content),
            *self._extract_md5_hashes(content),
            *self._extract_cves(content),
            *self._extract_asns(content),
        ]

        iocs = self._deduplicate(
            [
                *article.iocs,
                *extracted_iocs,
            ]
        )

        return replace(
            article,
            iocs=iocs,
        )

    @staticmethod
    def _build_searchable_content(article: Article) -> str:
        parts = (
            article.title,
            article.summary,
        )

        return " ".join(
            str(part)
            for part in parts
            if part is not None
        )

    @staticmethod
    def _extract_urls(content: str) -> list[IOC]:
        iocs: list[IOC] = []

        for match in _URL_PATTERN.finditer(content):
            value = match.group(0).rstrip(
                _TRAILING_URL_CHARACTERS
            )

            if value:
                iocs.append(
                    IOC(
                        type=IOCType.URL,
                        value=value,
                    )
                )

        return iocs

    @staticmethod
    def _extract_emails(content: str) -> list[IOC]:
        return [
            IOC(
                type=IOCType.EMAIL,
                value=match.group(0).lower(),
            )
            for match in _EMAIL_PATTERN.finditer(content)
        ]

    @staticmethod
    def _extract_ipv4_addresses(
        content: str,
    ) -> list[IOC]:
        iocs: list[IOC] = []

        for match in _IPV4_PATTERN.finditer(content):
            candidate = match.group(0)

            try:
                address = ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue

            iocs.append(
                IOC(
                    type=IOCType.IPV4,
                    value=str(address),
                )
            )

        return iocs

    @staticmethod
    def _extract_ipv6_addresses(
        content: str,
    ) -> list[IOC]:
        iocs: list[IOC] = []

        for match in _IPV6_PATTERN.finditer(content):
            candidate = match.group(0)

            try:
                address = ipaddress.IPv6Address(candidate)
            except ipaddress.AddressValueError:
                continue

            iocs.append(
                IOC(
                    type=IOCType.IPV6,
                    value=str(address),
                )
            )

        return iocs

    @staticmethod
    def _extract_domains(content: str) -> list[IOC]:
        iocs: list[IOC] = []

        for match in _DOMAIN_PATTERN.finditer(content):
            domain = match.group(0).lower()
            suffix = domain.rsplit(".", maxsplit=1)[-1]

            if suffix in _NON_DOMAIN_SUFFIXES:
                continue

            iocs.append(
                IOC(
                    type=IOCType.DOMAIN,
                    value=domain,
                )
            )

        return iocs

    @staticmethod
    def _extract_sha256_hashes(
        content: str,
    ) -> list[IOC]:
        return [
            IOC(
                type=IOCType.SHA256,
                value=match.group(0).lower(),
            )
            for match in _SHA256_PATTERN.finditer(content)
        ]

    @staticmethod
    def _extract_sha1_hashes(
        content: str,
    ) -> list[IOC]:
        return [
            IOC(
                type=IOCType.SHA1,
                value=match.group(0).lower(),
            )
            for match in _SHA1_PATTERN.finditer(content)
        ]

    @staticmethod
    def _extract_md5_hashes(
        content: str,
    ) -> list[IOC]:
        return [
            IOC(
                type=IOCType.MD5,
                value=match.group(0).lower(),
            )
            for match in _MD5_PATTERN.finditer(content)
        ]

    @staticmethod
    def _extract_cves(content: str) -> list[IOC]:
        return [
            IOC(
                type=IOCType.CVE,
                value=match.group(0).upper(),
            )
            for match in _CVE_PATTERN.finditer(content)
        ]

    @staticmethod
    def _extract_asns(content: str) -> list[IOC]:
        return [
            IOC(
                type=IOCType.ASN,
                value=match.group(0).upper(),
            )
            for match in _ASN_PATTERN.finditer(content)
        ]

    def _deduplicate(
        self,
        iocs: Iterable[IOC],
    ) -> list[IOC]:
        unique_iocs: list[IOC] = []
        seen: set[tuple[IOCType, str]] = set()

        for ioc in iocs:
            normalized_ioc = self._normalize(ioc)

            if normalized_ioc is None:
                continue

            key = (
                normalized_ioc.type,
                normalized_ioc.value.casefold(),
            )

            if key in seen:
                continue

            seen.add(key)
            unique_iocs.append(normalized_ioc)

        return unique_iocs

    @staticmethod
    def _normalize(ioc: IOC) -> IOC | None:
        value = ioc.value.strip()

        if not value:
            return None

        try:
            if ioc.type is IOCType.IPV4:
                value = str(
                    ipaddress.IPv4Address(value)
                )

            elif ioc.type is IOCType.IPV6:
                value = str(
                    ipaddress.IPv6Address(value)
                )

            elif ioc.type in {
                IOCType.DOMAIN,
                IOCType.EMAIL,
                IOCType.MD5,
                IOCType.SHA1,
                IOCType.SHA256,
            }:
                value = value.lower()

            elif ioc.type in {
                IOCType.CVE,
                IOCType.ASN,
            }:
                value = value.upper()

            elif ioc.type is IOCType.URL:
                value = value.rstrip(
                    _TRAILING_URL_CHARACTERS
                )

        except ipaddress.AddressValueError:
            return None

        return IOC(
            type=ioc.type,
            value=value,
        )