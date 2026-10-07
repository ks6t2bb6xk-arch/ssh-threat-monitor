"""Sanitize untrusted log text before it reaches output adapters."""

import unicodedata


MAX_USERNAME_LENGTH = 64


def sanitize_username(username: str | None, *, max_length: int = MAX_USERNAME_LENGTH) -> str | None:
    """Remove Unicode control/format characters and limit displayed length."""
    if username is None:
        return None
    if not isinstance(username, str):
        raise TypeError("username must be a string or None")
    if isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 1:
        raise ValueError("max_length must be a positive integer")
    safe = (char for char in username if not unicodedata.category(char).startswith("C"))
    result = ""
    for char in safe:
        if len(result) >= max_length:
            break
        result += char
    return result
