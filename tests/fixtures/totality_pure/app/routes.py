"""Every call besides the owner-checked load is PROVABLY unable to touch the database,
by import identity, receiver type, or transitive closure.  These routes must be SAFE."""
import anyio
import threading
from threading import RLock as reentrant_lock
from asyncio import to_thread
from dataclasses import dataclass
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException

from .lib import Formatter, describe, even_helper, get_current_user, get_session, logger, slugify
from .models import Doc, DocOut, Receipt

router = APIRouter()

ASSET = Path("asset.bin")


@router.get("/receipt")
def receipt():
    return Receipt()


@router.get("/process-locks")
def process_locks():
    return bool((threading.Lock(), reentrant_lock()))


@router.get("/plugin-lock")
def plugin_lock(threading):
    return threading.Lock()


@dataclass(frozen=True, slots=True)
class Snapshot:
    names: frozenset[str] = frozenset()

    def __post_init__(self):
        object.__setattr__(self, "names", frozenset(self.names))


@router.get("/snapshot")
def snapshot():
    return Snapshot()


@router.get("/write-unknown")
def write_unknown(target):
    object.__setattr__(target, "names", frozenset())


@dataclass(slots=True)
class SnapshotWithSetter:
    name: str

    def __post_init__(self):
        object.__setattr__(self, "display", self.name)

    @property
    def display(self):
        return self.name

    @display.setter
    def display(self, value):
        get_session().add(Doc(title=value))


@router.get("/snapshot-with-setter")
def snapshot_with_setter(name: str):
    return SnapshotWithSetter(name)


def load_asset():
    with ASSET.open("rb") as stream:
        return stream.read()


@router.get("/thread-file")
async def thread_file():
    return await to_thread(load_asset)


@router.get("/unknown-reader")
def unknown_reader(provider):
    with provider.open("rb") as stream:
        return stream.read()


@router.get("/asset-exists")
async def asset_exists(name: str):
    return await anyio.Path(name).exists()


@router.get("/other-exists")
async def other_exists(service=Depends(get_session)):
    return await service.Path("asset").exists()


@router.get("/pure/{doc_id}")
async def pure(doc_id: int, verbose: bool = False, session=Depends(get_session),
               current_user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    meta = {"kind": "doc"}
    label = slugify("My Title") if verbose else describe(meta)
    tags = "a,b".split(",")
    logger.info("served %s", label)
    out = DocOut(id=doc_id, title=Formatter().render(label)).model_dump()
    if even_helper(4) and len(tags) > 1 and meta.get("kind"):
        out["tags"] = sorted(tags)
    return out


@router.get("/pure-no-effects")
async def pure_no_effects(name: str = "x"):
    payload = {"name": name.strip().lower(), "ok": even_helper(2)}
    logger.info("ping %s", payload)
    return payload
