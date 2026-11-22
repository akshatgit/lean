"""Helpers and classes used to probe the purity oracle."""
import json
import logging
import uuid
from pathlib import Path

from sqlmodel import select

from .models import Doc

logger = logging.getLogger(__name__)
_SESSION = None  # stands in for a process-wide session/engine


def get_session(): ...


def get_current_user(): ...


# ---------------- provably effect-free ----------------
def slugify(title: str) -> str:
    return title.strip().lower().replace(" ", "-")


def describe(meta: dict, limit: int = 3) -> str:
    parts = [str(meta.get("kind", "doc")), json.dumps(sorted(meta)), uuid.uuid4().hex]
    logger.info("describe %s", parts)
    return ",".join(parts[:limit]) + Path("x").suffix


def even_helper(n: int) -> bool:
    return True if n <= 0 else odd_helper(n - 1)


def odd_helper(n: int) -> bool:
    return False if n <= 0 else even_helper(n - 1)


# ---------------- NOT effect-free, in ways a name-based check would miss ----------------
def calls_unknown(meta):
    return meta.lookup("x")          # untyped receiver: could be anything


def hidden_session_read(doc_id: int):
    return _SESSION.get(Doc, doc_id)  # no db/session parameter at all


def ping_reads(n: int) -> bool:       # mutual recursion where only one side touches data
    return n > 0 and pong_reads(n - 1)


def pong_reads(n: int) -> bool:
    _SESSION.exec(select(Doc))
    return ping_reads(n - 1)


def len(value):                       # shadows the builtin in this module  # noqa: A001
    return _SESSION.exec(select(Doc)).all()


def shadowed_len_user(items: list):
    return len(items)


class Registry(dict):
    """A dict subclass whose .get() hits the database."""

    def get(self, key, default=None):
        return _SESSION.get(Doc, key)


class Store:
    def load(self, key: int):
        return None

    @property
    def loader(self):
        return _SESSION.get


class DbStore(Store):
    def load(self, key: int):         # override touches the database
        return _SESSION.get(Doc, key)


class Touching:
    def __init__(self, doc_id: int):
        self.row = _SESSION.get(Doc, doc_id)


def passthrough(fn):
    return fn


def swallow_errors(fn):
    """A wrapper that turns the helper's denial into a normal return."""
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except Exception:  # noqa: BLE001
            return await args[0].get(Doc, args[1])
    return wrapper


@swallow_errors
async def load_checked(session, doc_id: int, user):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise PermissionError
    return doc


class Loader:
    """Injected with a bare `Depends()`; its constructor reads the database."""

    def __init__(self, doc_id: int):
        self.doc = _SESSION.get(Doc, doc_id)
