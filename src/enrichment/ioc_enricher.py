from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import replace
from urllib.parse import urlsplit, urlunsplit

from enrichment.text import refang, mask_references

from parser.models import Article, IOC, IOCType


_URL_PATTERN = re.compile(
    r"(?<![\w])https?://[^\s<>'\"]+",
    flags=re.IGNORECASE,
)

_EMAIL_PATTERN = re.compile(
    r"(?<![\w.@%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w-]|\.[\w.-])",
    flags=re.IGNORECASE,
)

_IPV4_PATTERN = re.compile(
    r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w]|\.[\w.])"
)

_IPV6_PATTERN = re.compile(
    r"(?<![\w:])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"[0-9A-Fa-f:.]*"
    r"(?![\w:])"
)

_DOMAIN_PATTERN = re.compile(
    r"(?<![\w.-])"
    r"(?:"
    r"[A-Z0-9]"
    r"(?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"\."
    r")+"
    r"[A-Z]{2,63}"
    r"(?![\w-]|\.[\w.-])",
    flags=re.IGNORECASE,
)

_SHA256_PATTERN = re.compile(
    r"(?<![\w])[A-Fa-f0-9]{64}(?![\w])"
)

_SHA1_PATTERN = re.compile(
    r"(?<![\w])[A-Fa-f0-9]{40}(?![\w])"
)

_MD5_PATTERN = re.compile(
    r"(?<![\w])[A-Fa-f0-9]{32}(?![\w])"
)

_CVE_PATTERN = re.compile(
    r"(?<![\w-])CVE-[0-9]{4}-[0-9]{4,}(?![\w-])",
    flags=re.IGNORECASE,
)

_ASN_PATTERN = re.compile(
    r"(?<![\w-])AS[0-9]{1,10}(?![\w-])",
    flags=re.IGNORECASE,
)

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
        content = refang(self._build_searchable_content(article))
        # Domains/IPs in paths and email local parts are not network hosts.
        network_text = mask_references(content)
        ipv6_text = _IPV6_PATTERN.sub(lambda match: " " * len(match.group()), network_text)
        urls = self._extract_urls(content)
        hosts: list[IOC] = []
        for url in urls:
            normalized = self._normalize(url)
            if normalized is None:
                continue
            host = urlsplit(normalized.value).hostname
            try:
                address = ipaddress.ip_address(host)
                kind = IOCType.IPV4 if address.version == 4 else IOCType.IPV6
            except ValueError:
                kind = IOCType.DOMAIN
            hosts.append(IOC(kind, host))

        extracted_iocs = [
            *urls,
            *hosts,
            *self._extract_emails(content),
            *self._extract_ipv4_addresses(ipv6_text),
            *self._extract_ipv6_addresses(network_text),
            *self._extract_domains(network_text),
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
            value = _trim_url(match.group(0))

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
            if re.search(r"\b(?:version|ver\.?|release|build)\s*[:=]?\s*$",
                         content[max(0, match.start() - 30):match.start()], re.IGNORECASE):
                continue

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
            candidate = match.group(0).rstrip(".")

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
                normalized_ioc.value if normalized_ioc.type == IOCType.URL else normalized_ioc.value.casefold(),
            )

            if key in seen:
                continue

            seen.add(key)
            unique_iocs.append(normalized_ioc)

        return unique_iocs

    @staticmethod
    def _normalize(ioc: IOC) -> IOC | None:
        if not isinstance(ioc, IOC) or not isinstance(ioc.value, str):
            return None
        try:
            kind = IOCType(ioc.type)
            value = refang(ioc.value.strip())
            if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
                return None
            if kind == IOCType.IPV4:
                value = str(ipaddress.IPv4Address(value))
            elif kind == IOCType.IPV6:
                value = str(ipaddress.IPv6Address(value))
            elif kind == IOCType.DOMAIN:
                value = _domain(value)
                if value is None:
                    return None
            elif kind == IOCType.EMAIL:
                if not _EMAIL_PATTERN.fullmatch(value) or len(value) > 254:
                    return None
                local, host = value.rsplit("@", 1)
                host = _domain(host)
                if not host or len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
                    return None
                value = local.lower() + "@" + host
            elif kind in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
                length = {IOCType.MD5: 32, IOCType.SHA1: 40, IOCType.SHA256: 64}[kind]
                if not re.fullmatch(r"[a-fA-F0-9]{" + str(length) + "}", value):
                    return None
                value = value.lower()
            elif kind == IOCType.CVE:
                if not _CVE_PATTERN.fullmatch(value):
                    return None
                value = value.upper()
            elif kind == IOCType.ASN:
                if not _ASN_PATTERN.fullmatch(value) or not 1 <= int(value[2:]) <= 4294967295:
                    return None
                value = "AS" + str(int(value[2:]))
            elif kind == IOCType.URL:
                parts = urlsplit(value)
                if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
                    return None
                if any(char.isspace() for char in value) or "\\" in value:
                    return None
                if parts.port is not None and not 1 <= parts.port <= 65535:
                    return None
                host = parts.hostname
                try:
                    address = ipaddress.ip_address(host)
                    host = "[" + str(address) + "]" if address.version == 6 else str(address)
                except ValueError:
                    host = _domain(host)
                    if host is None:
                        return None
                # Normalize scheme/host, preserving credentials, path, query and fragment case.
                credentials = parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc else ""
                port = ":" + str(parts.port) if parts.port is not None else ""
                value = urlunsplit((parts.scheme.lower(), credentials + host + port,
                                   parts.path, parts.query, parts.fragment))
        except (ValueError, TypeError, UnicodeError):
            return None
        return IOC(type=kind, value=value)


def _domain(value: str) -> str | None:
    if value.endswith(".."):
        return None
    try:
        value = value.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(value) > 253 or "." not in value:
        return None
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    if not re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]+", labels[-1]):
        return None
    return value


def _trim_url(value: str) -> str:
    value = value.rstrip(".,;:!?}>\"'")
    for opening, closing in (("(", ")"), ("[", "]")):
        while value.endswith(closing) and value.count(closing) > value.count(opening):
            value = value[:-1]
    return value
