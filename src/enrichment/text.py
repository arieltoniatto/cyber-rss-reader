"""Local text preparation for observable and name matching."""
import re


def refang(text: str) -> str:
    text = re.sub(r"\bhxxps?://", lambda match: "https://" if match.group().lower().startswith("hxxps") else "http://", text, flags=re.IGNORECASE)
    return text.replace("[.]", ".").replace("(.)", ".").replace("[@]", "@")


def mask_references(text: str) -> str:
    # Keep positions and sentence boundaries while ignoring link/email tokens.
    pattern = r"(?<![\w])(?:https?://[^\s<>\"']+|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})"
    return re.sub(pattern, lambda match: " " * len(match.group()), text, flags=re.IGNORECASE)
