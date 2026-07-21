class StorageError(Exception):
    """Base storage exception."""


class CacheCorrupted(StorageError):
    """Cache file could not be decoded."""