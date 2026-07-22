class ConfigurationError(Exception):
    """Base configuration exception."""


class FeedDirectoryNotFound(ConfigurationError):
    """Feed configuration directory does not exist."""


class InvalidConfiguration(ConfigurationError):
    """Configuration validation failed."""


class DuplicateFeedError(ConfigurationError):
    """Duplicate feed names or URLs detected."""