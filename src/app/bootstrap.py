"""Compatibility entry point for applications using the composition root."""
from app.container import ApplicationContainer


def bootstrap(**kwargs) -> ApplicationContainer:
    return ApplicationContainer(**kwargs)
