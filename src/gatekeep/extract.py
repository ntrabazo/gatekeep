"""Pull every scannable text out of a /v1/messages body, remembering where each came
from so redacted versions can be written back in place. Non-text blocks are never
scanned; unknown block types are skipped."""

from dataclasses import dataclass


@dataclass
class TextRef:
    path: tuple  # key path into the body, e.g. ("messages", 0, "content", 1, "text")
    text: str


def extract_texts(body: dict) -> list[TextRef]:
    refs: list[TextRef] = []

    system = body.get("system")
    if isinstance(system, str):
        refs.append(TextRef(("system",), system))
    elif isinstance(system, list):
        for i, block in enumerate(system):
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                refs.append(TextRef(("system", i, "text"), block["text"]))

    for i, msg in enumerate(body.get("messages") or []):
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            refs.append(TextRef(("messages", i, "content"), content))
        elif isinstance(content, list):
            for j, block in enumerate(content):
                if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                    refs.append(TextRef(("messages", i, "content", j, "text"), block["text"]))

    return refs


def apply_texts(body: dict, refs: list[TextRef], new_texts: list[str]) -> dict:
    """Write (possibly redacted) texts back into the body at their original paths."""
    for ref, new in zip(refs, new_texts):
        node = body
        for key in ref.path[:-1]:
            node = node[key]
        node[ref.path[-1]] = new
    return body
