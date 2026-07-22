
# Cybersecurity RSS Reader

A modular, terminal-based cybersecurity RSS feed reader built with Python 3.12+.

The project is designed with clean architecture principles, separation of concerns, and future scalability in mind. It supports multiple RSS feeds, categories, local caching, searching, topic extraction, and can be extended with databases, APIs, web interfaces, and plugins.

---

# Features

## Current Features

- Terminal-based interface
- RSS/Atom feed collection
- Multiple feed categories
- YAML-based configuration
- Concurrent feed downloads
- HTTP retries and timeouts
- Configurable User-Agent
- Article normalization
- Local JSON cache
- Cache expiration
- Duplicate article handling
- Search engine
- Keyword filtering
- Category filtering
- Source filtering
- Fuzzy matching
- Topic extraction
- Rich terminal output

---

## Planned Features

- SQLite/PostgreSQL storage backend
- REST API
- Web interface
- Plugin system
- AI-generated summaries
- CVE lookup
- IOC extraction
- MITRE ATT&CK mapping
- Elasticsearch integration
- Docker deployment

---

# Architecture

The project follows a modular architecture based on separation of responsibilities.

High-level data flow:
```
            +----------------+
            | YAML Feeds     |
            | Configuration  |
            +-------+--------+
                    |
                    v
            +---------------+
            | Config Loader |
            +-------+-------+
                    |
                    v
            +---------------+
            | RSS Fetcher   |
            +-------+-------+
                    |
                    v
            +---------------+
            | RSS Parser    |
            +-------+-------+
                    |
                    v
            +---------------+
            | Article Model |
            +-------+-------+
                    |
      +-------------+-------------+
      |                           |
      v                           v


+----------------+          +----------------+
| Storage Layer  |          | Search Engine  |
| JSON / SQLite  |          | Filters/Fuzzy  |
+----------------+          +----------------+


                    |
                    v

            +---------------+
            | Terminal CLI |
            | Typer + Rich |
            +---------------+

```


---

# Project Structure

```

cyber-rss-reader/

├── src/
│
│   ├── app/
│   │   ├── container.py
│   │   └── main.py
│   │
│   ├── cli/
│   │   ├── app.py
│   │   ├── dependencies.py
│   │   └── commands/
│   │
│   ├── config/
│   │   ├── loader.py
│   │   ├── models.py
│   │   └── feeds/
│   │       ├── news.yaml
│   │       ├── malware_research.yaml
│   │       └── exploit_research.yaml
│   │
│   ├── feeds/
│   │   ├── fetcher.py
│   │   └── models.py
│   │
│   ├── parser/
│   │   ├── parser.py
│   │   ├── models.py
│   │   └── utils.py
│   │
│   ├── search/
│   │   ├── engine.py
│   │   ├── filters.py
│   │   └── models.py
│   │
│   ├── storage/
│   │   ├── interfaces.py
│   │   ├── json_storage.py
│   │   └── models.py
│   │
│   ├── topics/
│   │   ├── extractor.py
│   │   └── models.py
│   │
│   └── services/
│       ├── article_service.py
│       ├── search_service.py
│       └── topic_service.py
│
├── data/
│   └── articles.json
│
├── tests/
│
├── requirements.txt
├── pyproject.toml
└── README.md

````

---

# Installation

## Requirements

- Python >= 3.12
- pip
- virtual environment

---

## Clone repository

```bash
git clone <repository-url>

cd cyber-rss-reader
````

---

## Create virtual environment

Linux:

```bash
python3 -m venv .venv

source .venv/bin/activate
```

Windows:

```powershell
python -m venv .venv

.venv\Scripts\activate
```

---

## Install dependencies

```bash
pip install -r requirements.txt
```

---

## Install as CLI application

Install in editable mode:

```bash
pip install -e .
```

After installation:

```bash
rss --help
```

---

# Usage

## Update feeds

Downloads feeds and updates the local cache.

```bash
rss update
```

Example:

```
Updating feeds...

Feeds downloaded : 11
Articles parsed  : 265
Articles saved   : 265
Source           : Network

Update complete.
```

---

## Show latest articles

```bash
rss latest
```

Example:

```
Published   Source          Category
2026-06-01  CyberScoop      news
2026-05-30  BleepingComp.   malware_research

Title:
Hackers Used Meta's AI Support Bot to Seize Instagram Accounts
```

---

## Search articles

Search by keyword:

```bash
rss search malware
```

Search by category:

```bash
rss search exploit --category exploit_research
```

Search by source:

```bash
rss search vulnerability --source "BleepingComputer"
```

---

## Show topics

Extract cybersecurity topics:

```bash
rss topics
```

Example:

```
Topic                    Score

ransomware               0.82
zero day exploit         0.76
malware campaign         0.71
```

---

## Filter categories

```bash
rss category news
```

---

## Filter sources

```bash
rss source CyberScoop
```

---

# Feed Configuration

Feeds are stored as YAML files.

Each category has its own file.

Example:

```
src/config/feeds/
├── news.yaml
├── malware_research.yaml
└── exploit_research.yaml
```

---

## Add a new feed

Edit the desired category file.

Example:

`news.yaml`

```yaml
category: news

feeds:

  - name: Example Security News
    url: https://example.com/rss.xml
    enabled: true
    description: Security news source
```

The application automatically loads new feeds.

No code changes are required.

---

# Disable a feed

Change:

```yaml
enabled: true
```

to:

```yaml
enabled: false
```

Example:

```yaml
feeds:

  - name: Old Feed
    url: https://example.com/rss.xml
    enabled: false
```

Disabled feeds are ignored automatically.

---

# Add a New Category

Create a new YAML file.

Example:

```
src/config/feeds/cloud_security.yaml
```

Content:

```yaml
category: cloud_security

feeds:

  - name: Cloud Security News
    url: https://example.com/feed.xml
    enabled: true
```

Restart the application.

The new category is automatically detected.

---

# Storage Layer

Currently:

```
ArticleRepository
        |
        v
JsonArticleRepository
```

Articles are stored in:

```
data/articles.json
```

Example:

```json
{
  "created_at": "2026-07-22",
  "articles": []
}
```

---

# Replacing JSON with SQLite

The storage layer uses an interface:

```
storage/interfaces.py
```

Current:

```
ArticleRepository
        |
        v
JsonArticleRepository
```

Future:

```
ArticleRepository
        |
        v
SQLiteArticleRepository
```

Implementation steps:

1. Create:

```
storage/sqlite_storage.py
```

2. Implement:

```python
class SQLiteArticleRepository(
    ArticleRepository
):
    ...
```

3. Replace dependency injection:

Current:

```python
JsonArticleRepository(...)
```

Future:

```python
SQLiteArticleRepository(...)
```

No service changes are required.

---

# Creating Plugins

Plugins can extend functionality without modifying core modules.

Example:

```
plugins/

    my_plugin/

        __init__.py
        plugin.py
```

Plugin interface:

```python
class Plugin:

    def initialize(self):
        pass

    def execute(self):
        pass
```

Possible plugins:

* custom exporters
* alert systems
* integrations
* additional enrichment modules

---

# Dependencies

Main dependencies:

| Package    | Purpose            |
| ---------- | ------------------ |
| httpx      | HTTP client        |
| feedparser | RSS parsing        |
| pydantic   | Data validation    |
| typer      | CLI framework      |
| rich       | Terminal UI        |
| rapidfuzz  | Fuzzy searching    |
| pyyaml     | YAML configuration |

---

# Development

Run tests:

```bash
pytest
```

Run with debug logging:

```bash
rss update --log-level DEBUG
```

---

# Roadmap

## Version 0.2

* Better feed validation
* More search operators
* Improved topic extraction
* Better logging

---

## Version 0.3

* SQLite storage
* Database migrations
* Article history

---

## Version 0.4

* AI summaries
* Automatic article classification
* Threat intelligence enrichment

---

## Version 0.5

* CVE lookup
* Vulnerability correlation
* IOC extraction

---

## Version 0.6

* MITRE ATT&CK mapping
* Threat actor tracking

---

## Version 0.7

* REST API

Example:

```
GET /articles
GET /search
GET /topics
```

---

## Version 0.8

* Web UI

Features:

* dashboards
* search interface
* analytics
* feed management

---

## Version 1.0

* Docker deployment
* Production database
* Plugin marketplace
* Enterprise-ready deployment

---

# License

MIT License


