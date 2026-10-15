"""One spelling per name: the comparison every name check uses.

Two writings of the same name (an accent composed or decomposed, a full-width letter, a
no-break space, a zero-width space, a soft hyphen) must not be two different subjects, or a
listed party gets through screening by being typed a different way. The result is only for
comparing: nothing displayed or signed is ever replaced by it."""

from __future__ import annotations

import unicodedata


def normalize_name(name: str) -> str:
    text = unicodedata.normalize("NFKC", name)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")  # invisible format characters
    text = unicodedata.normalize("NFKC", text.casefold())                   # casefold can leave non-NFKC forms
    return " ".join(text.split())
