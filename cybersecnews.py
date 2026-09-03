import asyncio
import hashlib
import ipaddress
import logging
import os
import random
import re
import secrets
import socket
import sqlite3
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, unquote_plus
from xml.etree import ElementTree as ET

import feedparser
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 60
CACHE_TTL = 300
MAX_HEADLINES = 15
HISTORY_PAGE = 15
MAX_FEED_BYTES = 3_000_000
MAX_PREVIEW_BYTES = 1_500_000
MAX_BODY_BYTES = 300_000
MAX_REDIRECTS = 3
BACKOFF_BASE = 30
BACKOFF_CAP = 1800
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}
STRIKE_THRESHOLD = 3
STRIKE_WINDOW = 600
BLOCK_DURATION = 900
PREVIEW_CACHE_TTL = 600
PREVIEW_CACHE_MAX = 40
PREVIEW_TEXT_LIMIT = 8000
EXPORT_LIMIT = 2000
OPML_MAX_OUTLINES = 50
USER_AGENT = "CyberNewsAggregator/1.0 (local research instance)"
FEED_TIMEOUT = httpx.Timeout(12.0, connect=6.0)
PREVIEW_TIMEOUT = httpx.Timeout(12.0, connect=6.0)
DEFAULT_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH") or os.path.join(APP_DIR, "cybernews_data.db")
BG_INTERVAL = max(60, min(3600, int(os.environ.get("BG_REFRESH", "300") or 300)))
TRUST_PROXY = os.environ.get("TRUST_PROXY", "").lower() == "1"
_PROXY_RAW = os.environ.get("FEED_PROXY", "").strip()
_PROXY = _PROXY_RAW if urlparse(_PROXY_RAW).scheme.lower() in ("socks5", "http", "https") else ""
if _PROXY_RAW and not _PROXY:
    logging.getLogger("cybernews").warning("FEED_PROXY ignored, unsupported scheme")

DEFAULT_FEEDS: Dict[str, str] = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "The Record": "https://therecord.media/feed/",
    "CyberScoop": "https://www.cyberscoop.com/feed",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "Cybersecurity News": "https://cybersecuritynews.com/feed/",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
}

FILTER_TERMS: Dict[str, re.Pattern] = {
    "ransomware": re.compile(r"\bransomware\b", re.I),
    "zero-day": re.compile(r"\bzero[\s-]?days?\b", re.I),
    "cve": re.compile(r"\bcve-\d{4}-\d{4,7}\b", re.I),
    "apt": re.compile(r"\bAPT(?:[- ]\d{1,4})?\b"),
    "supply-chain": re.compile(r"\bsupply[\s-]?chain\b", re.I),
    "malware": re.compile(r"\bmalware\b|\bbackdoor\b|\brat\b", re.I),
    "breach": re.compile(r"\bbreach(?:es|ed)?\b|\bleak(?:ed)?\b", re.I),
    "exploit": re.compile(r"\bexploit(?:s|ed)?\b|\bpoc\b", re.I),
}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

_THREAT_PATTERNS = [
    re.compile(r"union[\s(+]+(?:all[\s(+]+)?select", re.I),
    re.compile(r";\s*drop\s+(?:table|database)\b", re.I),
    re.compile(r"'\s*(?:or|and)\s*'[^']*'\s*=\s*'", re.I),
    re.compile(r"(?:'|\d)\s*=\s*\d\s*(?:--|#)"),
    re.compile(r"<script\b", re.I),
    re.compile(r"<iframe\b", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"(?:\.\./){2,}"),
    re.compile(r"%2e%2e(?:%2f|%5c)", re.I),
    re.compile(r"\x00"),
    re.compile(r"\$\{\s*jndi\s*:", re.I),
    re.compile(r"\bon(?:error|load|click|focus)\s*=", re.I),
    re.compile(r"/etc/(?:passwd|shadow)", re.I),
]

_strike_store: Dict[str, List[float]] = {}
_block_store: Dict[str, float] = {}
_cache: Dict[str, Dict[str, Any]] = {}
_preview_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_rate: Dict[str, List[float]] = {}
_rate_lock = asyncio.Lock()
_bg_task: Optional[asyncio.Task] = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("cybernews")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_text(text: str, max_len: int = 500) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[\x00-\x1f\x7f]", "", text)
    return text.strip()[:max_len]


def _client_id(request: Request) -> str:
    if TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for", "")
        ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    else:
        ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")[:120]
    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:32]


def _threat_score(text: str) -> int:
    score = 0
    for pattern in _THREAT_PATTERNS:
        if pattern.search(text):
            score += 1
    return score


def _is_blocked(cid: str) -> bool:
    until = _block_store.get(cid)
    if until is None:
        return False
    if time.time() >= until:
        _block_store.pop(cid, None)
        _strike_store.pop(cid, None)
        return False
    return True


def _register_strike(cid: str) -> None:
    now = time.time()
    strikes = [t for t in _strike_store.get(cid, []) if now - t < STRIKE_WINDOW]
    strikes.append(now)
    _strike_store[cid] = strikes
    if len(strikes) >= STRIKE_THRESHOLD:
        _block_store[cid] = now + BLOCK_DURATION


def _url_precheck(url: str) -> Optional[str]:
    if not url or len(url) > 2000:
        return "Invalid URL"
    try:
        p = urlparse(url)
    except Exception:
        return "Invalid URL"
    if p.scheme.lower() not in ALLOWED_SCHEMES:
        return "Only http and https schemes are allowed"
    if not p.netloc or p.username or p.password:
        return "Invalid host"
    host = p.hostname or ""
    if not host or len(host) > 253:
        return "Invalid host"
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
        return "Invalid host characters"
    if "." not in host:
        return "Invalid host"
    try:
        port = p.port
    except ValueError:
        return "Invalid port"
    if port is not None and port not in ALLOWED_PORTS:
        return "Port not allowed"
    if len(p.query or "") > 500:
        return "Query too long"
    if p.fragment:
        return "Fragments not allowed"
    return None


async def _url_ssrf_check(url: str) -> Tuple[bool, str]:
    pre = _url_precheck(url)
    if pre:
        return False, pre
    host = urlparse(url).hostname or ""
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
    except (OSError, UnicodeError):
        return False, "DNS resolution failed"
    if not infos:
        return False, "DNS resolution failed"
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            return False, "Invalid resolved address"
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if (
            not ip.is_global
            or ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False, "Host resolves to a restricted address"
    return True, ""


def _link_ok(url: str) -> bool:
    if not url or len(url) > 2000:
        return False
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme.lower() not in ALLOWED_SCHEMES:
        return False
    if not p.netloc or p.username or p.password:
        return False
    host = (p.hostname or "").lower()
    if not host or any(host == d or host.endswith("." + d) for d in ("localhost", "localhost.localdomain")):
        return False
    if host.startswith(("127.", "10.", "192.168.", "169.254.", "0.")) or host == "::1":
        return False
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            return False
    except ValueError:
        pass
    try:
        port = p.port
        if port is not None and port not in ALLOWED_PORTS:
            return False
    except ValueError:
        return False
    return True


class FeedFetchError(Exception):
    pass


def _make_client(timeout: httpx.Timeout) -> httpx.AsyncClient:
    kwargs: Dict[str, Any] = dict(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, text/html;q=0.8",
            "Accept-Language": "en",
        },
    )
    if _PROXY:
        try:
            return httpx.AsyncClient(proxy=_PROXY, **kwargs)
        except TypeError:
            try:
                return httpx.AsyncClient(proxies=_PROXY, **kwargs)
            except TypeError:
                raise FeedFetchError("Proxy configuration unsupported")
        except ImportError:
            raise FeedFetchError("Proxy transport requires httpx[socks]")
    return httpx.AsyncClient(**kwargs)


async def _safe_get(url: str, max_bytes: int, timeout: httpx.Timeout) -> Tuple[int, str, bytes]:
    current = url
    async with _make_client(timeout) as client:
        for _ in range(MAX_REDIRECTS + 1):
            ok, err = await _url_ssrf_check(current)
            if not ok:
                raise FeedFetchError(err or "Blocked target")
            req = client.build_request("GET", current)
            resp = await client.send(req, stream=True)
            try:
                if resp.is_redirect:
                    loc = resp.headers.get("location")
                    if not loc:
                        raise FeedFetchError("Bad redirect")
                    nxt = urljoin(current, loc)
                    if urlparse(nxt).scheme.lower() not in ALLOWED_SCHEMES:
                        raise FeedFetchError("Bad redirect")
                    current = nxt
                    continue
                if resp.status_code < 200 or resp.status_code >= 300:
                    raise FeedFetchError("Upstream error")
                buf = bytearray()
                async for chunk in resp.aiter_bytes(65536):
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise FeedFetchError("Response too large")
                return resp.status_code, (resp.headers.get("content-type") or "").lower(), bytes(buf)
            finally:
                await resp.aclose()
    raise FeedFetchError("Too many redirects")


class _TextExtract(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.title_parts: List[str] = []
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("script", "style", "noscript", "svg", "template"):
            self._skip += 1
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript", "svg", "template") and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        t = data.strip()
        if not t:
            return
        if self._in_title:
            self.title_parts.append(t)
        else:
            self.parts.append(t)


class Database:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=4000")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create()
        self._seed()

    def _create(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sources(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    custom INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS articles(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_url TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    link TEXT NOT NULL UNIQUE,
                    published TEXT,
                    summary TEXT,
                    first_seen TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source_url);
                CREATE INDEX IF NOT EXISTS idx_articles_seen ON articles(first_seen);
                CREATE TABLE IF NOT EXISTS fetch_state(
                    url TEXT PRIMARY KEY,
                    fail_count INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL DEFAULT 0,
                    last_ok TEXT
                );
                """
            )

    def _seed(self) -> None:
        with self._lock, self._conn:
            for name, url in DEFAULT_FEEDS.items():
                self._conn.execute(
                    "INSERT OR IGNORE INTO sources(name, url, enabled, custom, created_at) VALUES(?,?,1,0,?)",
                    (name, url, _utcnow()),
                )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def sources(self, enabled_only: bool = False) -> List[sqlite3.Row]:
        sql = "SELECT id, name, url, enabled, custom FROM sources"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY custom, id"
        with self._lock:
            return self._conn.execute(sql).fetchall()

    def list_sources(self) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                """SELECT s.id, s.name, s.url, s.enabled, s.custom, s.created_at, f.last_ok
                   FROM sources s LEFT JOIN fetch_state f ON f.url = s.url
                   ORDER BY s.custom, s.id"""
            ).fetchall()

    def get_source(self, sid: int) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT id, name, url, enabled, custom FROM sources WHERE id=?", (sid,)).fetchone()

    def add_source(self, name: str, url: str) -> bool:
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT INTO sources(name, url, enabled, custom, created_at) VALUES(?,?,1,1,?)",
                    (name, url, _utcnow()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def set_enabled(self, sid: int, enabled: bool) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("UPDATE sources SET enabled=? WHERE id=?", (1 if enabled else 0, sid))
        return cur.rowcount > 0

    def delete_source(self, sid: int) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM sources WHERE id=? AND custom=1", (sid,))
        return cur.rowcount > 0

    def save_articles(self, rows: List[Tuple[str, str, str, str, Optional[str], Optional[str]]]) -> None:
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO articles(source_url, source_name, title, link, published, summary, first_seen) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(link) DO NOTHING",
                [(r[0], r[1], r[2], r[3], r[4], r[5], _utcnow()) for r in rows],
            )

    def first_seen_map(self, links: List[str]) -> Dict[str, str]:
        if not links:
            return {}
        marks = ",".join("?" for _ in links)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT link, first_seen FROM articles WHERE link IN ({marks})", links
            ).fetchall()
        return {r["link"]: r["first_seen"] for r in rows}

    def articles_for(self, url: str, limit: int) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT title, link, published, summary, source_name, first_seen FROM articles "
                "WHERE source_url=? ORDER BY first_seen DESC, id DESC LIMIT ?",
                (url, limit),
            ).fetchall()

    def history(self, offset: int, limit: int, source: Optional[str], term: Optional[str]) -> List[sqlite3.Row]:
        sql = "SELECT title, link, published, summary, source_name, first_seen FROM articles"
        cond: List[str] = []
        params: List[Any] = []
        if source:
            cond.append("source_url = ?")
            params.append(source)
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY first_seen DESC, id DESC LIMIT ? OFFSET ?"
        params.append(limit * 6 if term else limit)
        params.append(offset)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        if term:
            pat = FILTER_TERMS[term]
            rows = [r for r in rows if pat.search((r["title"] or "") + " " + (r["summary"] or ""))][:limit]
        return rows

    def all_articles(self, limit: int) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT title, link, published, summary, source_name AS source, source_url, first_seen "
                "FROM articles ORDER BY first_seen DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def get_state(self, url: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT fail_count, next_attempt, last_ok FROM fetch_state WHERE url=?", (url,)
            ).fetchone()

    def record_ok(self, url: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO fetch_state(url, fail_count, next_attempt, last_ok) VALUES(?,0,0,?) "
                "ON CONFLICT(url) DO UPDATE SET fail_count=0, next_attempt=0, last_ok=excluded.last_ok",
                (url, _utcnow()),
            )

    def record_fail(self, url: str) -> None:
        row = self.get_state(url)
        fc = (row["fail_count"] if row else 0) + 1
        delay = min(BACKOFF_BASE * (2 ** min(fc, 6)), BACKOFF_CAP)
        jitter = random.uniform(0, delay * 0.15)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO fetch_state(url, fail_count, next_attempt, last_ok) VALUES(?,?,?,NULL) "
                "ON CONFLICT(url) DO UPDATE SET fail_count=excluded.fail_count, next_attempt=excluded.next_attempt",
                (url, fc, time.time() + delay + jitter),
            )


try:
    DB = Database(DB_PATH)
except Exception:
    logger.critical("Database initialization failed")
    raise SystemExit(1)


def _snapshot(url: str, name: str, error: Optional[str] = None) -> "SourceResponse":
    rows = DB.articles_for(url, MAX_HEADLINES)
    headlines = [
        Headline(
            title=r["title"],
            link=r["link"],
            published=r["published"],
            summary=r["summary"],
            source=r["source_name"],
            first_seen=r["first_seen"],
        )
        for r in rows
    ]
    state = DB.get_state(url)
    fetched = state["last_ok"] if state and state["last_ok"] else _utcnow()
    return SourceResponse(source=name, url=url, headlines=headlines, fetched_at=fetched, error=error, stale=True)


async def fetch_feed(name: str, url: str, force: bool = False, respect_backoff: bool = True) -> "SourceResponse":
    now = time.time()
    ck = hashlib.sha256(url.encode()).hexdigest()
    if not force:
        cached = _cache.get(ck)
        if cached and now - cached["ts"] < CACHE_TTL:
            return cached["data"]
    if respect_backoff:
        state = DB.get_state(url)
        if state and state["next_attempt"] and state["next_attempt"] > now:
            return _snapshot(url, name, error="Temporarily backing off, showing last snapshot")
    try:
        status, ctype, body = await _safe_get(url, MAX_FEED_BYTES, FEED_TIMEOUT)
        parsed = await asyncio.to_thread(feedparser.parse, body)
        entries = list(getattr(parsed, "entries", []) or [])
        if getattr(parsed, "bozo", False) and not entries:
            raise FeedFetchError("Malformed feed")
        rows: List[Tuple[str, str, str, str, Optional[str], Optional[str]]] = []
        seen_links: List[str] = []
        for entry in entries[:MAX_HEADLINES]:
            title = _sanitize_text(getattr(entry, "title", "") or "Untitled", 500)
            link = _sanitize_text(getattr(entry, "link", "") or "", 2000)
            if not title or not link or not _link_ok(link):
                continue
            published = None
            for attr in ("published_parsed", "updated_parsed"):
                st = getattr(entry, attr, None)
                if st:
                    try:
                        published = datetime(*st[:6], tzinfo=timezone.utc).isoformat()
                        break
                    except Exception:
                        pass
            summary = _sanitize_text(
                getattr(entry, "summary", "") or getattr(entry, "description", "") or "", 800
            )
            rows.append((url, name, title, link, published, summary))
            seen_links.append(link)
        if not entries:
            raise FeedFetchError("Empty feed")
        DB.save_articles(rows)
        DB.record_ok(url)
        fsm = DB.first_seen_map(seen_links)
        headlines = [
            Headline(
                title=r[2],
                link=r[3],
                published=r[4],
                summary=r[5],
                source=name,
                first_seen=fsm.get(r[3]),
            )
            for r in rows
        ]
        result = SourceResponse(source=name, url=url, headlines=headlines, fetched_at=_utcnow(), error=None, stale=False)
        _cache[ck] = {"ts": now, "data": result}
        return result
    except Exception as exc:
        logger.info("Feed fetch failed for %s: %s", name, type(exc).__name__)
        DB.record_fail(url)
        return _snapshot(url, name, error="Feed unavailable, showing last snapshot")


async def _bg_loop() -> None:
    while True:
        try:
            for s in DB.sources(enabled_only=True):
                await fetch_feed(s["name"], s["url"], force=True, respect_backoff=True)
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.info("Background refresh cycle error")
        await asyncio.sleep(BG_INTERVAL)


class Headline(BaseModel):
    title: str = Field(..., max_length=500)
    link: str = Field(..., max_length=2000)
    published: Optional[str] = None
    summary: Optional[str] = Field(default=None, max_length=1000)
    source: str = Field(..., max_length=100)
    first_seen: Optional[str] = None


class SourceResponse(BaseModel):
    source: str = Field(..., max_length=100)
    url: str = Field(..., max_length=2000)
    headlines: List[Headline] = Field(default_factory=list)
    fetched_at: str
    error: Optional[str] = None
    stale: bool = False


class SourceOut(BaseModel):
    id: int
    name: str
    url: str
    enabled: bool
    custom: bool
    created_at: str
    last_ok: Optional[str] = None


class SourceIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    url: str = Field(..., min_length=8, max_length=2000)

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        v = _sanitize_text(v, 100)
        if not v:
            raise ValueError("Name required")
        return v

    @field_validator("url")
    @classmethod
    def clean_url(cls, v: str) -> str:
        v = v.strip()
        if _url_precheck(v) is not None:
            raise ValueError("URL rejected")
        return v


class EnabledIn(BaseModel):
    enabled: bool


class OPMLIn(BaseModel):
    opml: str = Field(..., min_length=10, max_length=300_000)

    @field_validator("opml")
    @classmethod
    def reject_dtd(cls, v: str) -> str:
        low = v.lower()
        if "<!doctype" in low or "<!entity" in low:
            raise ValueError("Rejected content")
        return v


class GuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        if len(request.url.path) > 1024 or len(request.url.query or "") > 2048:
            return JSONResponse(status_code=400, content={"detail": "Request too long"})
        cid = _client_id(request)
        if _is_blocked(cid):
            await asyncio.sleep(0.5)
            return JSONResponse(status_code=403, content={"detail": "Request blocked"})
        raw = request.url.path + "?" + (request.url.query or "")
        decoded = unquote_plus(raw)
        score = _threat_score(raw) + _threat_score(decoded)
        if score >= 2:
            _register_strike(cid)
            logger.warning("Blocked suspicious request score=%s client=%s path=%s", score, cid, request.url.path[:64])
            await asyncio.sleep(0.5)
            return JSONResponse(status_code=403, content={"detail": "Request blocked"})
        if request.method in ("POST", "PATCH", "DELETE"):
            if request.headers.get("x-requested-with", "").lower() != "xmlhttprequest":
                return JSONResponse(status_code=403, content={"detail": "Forbidden"})
            cl = request.headers.get("content-length", "")
            if cl.isdigit() and int(cl) > MAX_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Payload too large"})
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        cid = _client_id(request)
        now = time.time()
        async with _rate_lock:
            times = [t for t in _rate.get(cid, []) if now - t < RATE_LIMIT_WINDOW]
            if len(times) >= RATE_LIMIT_MAX:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
                )
            times.append(now)
            _rate[cid] = times
            if len(_rate) > 5000:
                for k in [k for k, v in _rate.items() if not v or now - v[-1] > RATE_LIMIT_WINDOW]:
                    _rate.pop(k, None)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if "content-security-policy" not in response.headers:
            response.headers["Content-Security-Policy"] = DEFAULT_CSP
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _bg_task
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        logger.warning("Running as root is discouraged for security")
    _bg_task = asyncio.create_task(_bg_loop())
    yield
    if _bg_task:
        _bg_task.cancel()
        try:
            await _bg_task
        except asyncio.CancelledError:
            pass
    _cache.clear()
    _rate.clear()
    DB.close()


app = FastAPI(
    title="CyberSec News Aggregator",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-Requested-With"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GuardMiddleware)


def _filter_source_response(r: SourceResponse, term: str) -> SourceResponse:
    pat = FILTER_TERMS[term]
    kept = [h for h in r.headlines if pat.search((h.title or "") + " " + (h.summary or ""))]
    return r.model_copy(update={"headlines": kept})


@app.get("/api/feeds", response_model=List[SourceResponse])
async def read_feeds(
    filter_term: Optional[str] = Query(default=None, alias="filter", max_length=40),
    refresh: bool = Query(default=False),
):
    term = None
    if filter_term:
        f = filter_term.strip().lower()
        if f not in FILTER_TERMS:
            raise HTTPException(status_code=400, detail="Unknown filter term")
        term = f
    sources = DB.sources(enabled_only=True)
    tasks = [
        fetch_feed(s["name"], s["url"], force=refresh, respect_backoff=not refresh)
        for s in sources
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    output: List[SourceResponse] = []
    for s, r in zip(sources, results):
        if isinstance(r, SourceResponse):
            output.append(_filter_source_response(r, term) if term else r)
        else:
            output.append(
                SourceResponse(
                    source=s["name"],
                    url=s["url"],
                    headlines=[],
                    fetched_at=_utcnow(),
                    error="Internal error",
                    stale=True,
                )
            )
    return output


@app.get("/api/history", response_model=List[Headline])
async def read_history(
    offset: int = Query(default=0, ge=0, le=100000),
    limit: int = Query(default=HISTORY_PAGE, ge=1, le=50),
    source: Optional[str] = Query(default=None, max_length=2000),
    filter_term: Optional[str] = Query(default=None, alias="filter", max_length=40),
):
    term = None
    if filter_term:
        f = filter_term.strip().lower()
        if f not in FILTER_TERMS:
            raise HTTPException(status_code=400, detail="Unknown filter term")
        term = f
    if source and not _link_ok(source):
        raise HTTPException(status_code=400, detail="Invalid source")
    rows = DB.history(offset, limit, source, term)
    return [
        Headline(
            title=r["title"],
            link=r["link"],
            published=r["published"],
            summary=r["summary"],
            source=r["source_name"],
            first_seen=r["first_seen"],
        )
        for r in rows
    ]


@app.get("/api/sources", response_model=List[SourceOut])
async def read_sources():
    return [
        SourceOut(
            id=r["id"],
            name=r["name"],
            url=r["url"],
            enabled=bool(r["enabled"]),
            custom=bool(r["custom"]),
            created_at=r["created_at"],
            last_ok=r["last_ok"],
        )
        for r in DB.list_sources()
    ]


@app.post("/api/sources", response_model=SourceOut, status_code=201)
async def create_source(payload: SourceIn):
    ok, err = await _url_ssrf_check(payload.url)
    if not ok:
        raise HTTPException(status_code=400, detail=err or "URL rejected")
    if not DB.add_source(payload.name, payload.url):
        raise HTTPException(status_code=409, detail="Feed already exists")
    row = DB._conn.execute("SELECT id, name, url, enabled, custom, created_at FROM sources WHERE url=?", (payload.url,)).fetchone()
    return SourceOut(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        enabled=bool(row["enabled"]),
        custom=bool(row["custom"]),
        created_at=row["created_at"],
        last_ok=None,
    )


@app.patch("/api/sources/{sid}", response_model=SourceOut)
async def modify_source(sid: int = Path(..., ge=1, le=1_000_000_000), payload: EnabledIn = None):
    if payload is None:
        raise HTTPException(status_code=400, detail="Invalid body")
    if not DB.set_enabled(sid, payload.enabled):
        raise HTTPException(status_code=404, detail="Source not found")
    row = DB.get_source(sid)
    state = DB.get_state(row["url"])
    return SourceOut(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        enabled=bool(row["enabled"]),
        custom=bool(row["custom"]),
        created_at=_utcnow(),
        last_ok=state["last_ok"] if state else None,
    )


@app.delete("/api/sources/{sid}")
async def remove_source(sid: int = Path(..., ge=1, le=1_000_000_000)):
    row = DB.get_source(sid)
    if not row:
        raise HTTPException(status_code=404, detail="Source not found")
    if not row["custom"]:
        raise HTTPException(status_code=400, detail="Only custom feeds can be removed")
    DB.delete_source(sid)
    return {"deleted": True}


@app.get("/api/preview")
async def article_preview(url: str = Query(..., max_length=2000)):
    pre = _url_precheck(url)
    if pre:
        raise HTTPException(status_code=400, detail=pre)
    key = hashlib.sha256(url.encode()).hexdigest()
    now = time.time()
    hit = _preview_cache.get(key)
    if hit and now - hit[0] < PREVIEW_CACHE_TTL:
        return hit[1]
    ok, err = await _url_ssrf_check(url)
    if not ok:
        raise HTTPException(status_code=400, detail=err or "URL rejected")
    try:
        status, ctype, body = await _safe_get(url, MAX_PREVIEW_BYTES, PREVIEW_TIMEOUT)
    except FeedFetchError:
        raise HTTPException(status_code=502, detail="Preview unavailable")
    if ctype.startswith("image/") or ctype.startswith("video/") or ctype.startswith("audio/"):
        result = {"title": "Binary content", "text": "This content type cannot be previewed as text.", "truncated": False}
    else:
        m = re.search(r"charset=([\w\-]+)", ctype)
        enc = m.group(1) if m else "utf-8"
        try:
            text = body.decode(enc, errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")
        parser = _TextExtract()
        await asyncio.to_thread(parser.feed, text)
        body_text = re.sub(r"\s+", " ", " ".join(parser.parts)).strip()[:PREVIEW_TEXT_LIMIT]
        title = re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip()[:200]
        if not title and parser.parts:
            title = parser.parts[0][:200]
        result = {"title": title or url, "text": body_text or "(No extractable content)", "truncated": len(body_text) >= PREVIEW_TEXT_LIMIT}
    _preview_cache[key] = (now, result)
    if len(_preview_cache) > PREVIEW_CACHE_MAX:
        oldest = min(_preview_cache, key=lambda k: _preview_cache[k][0])
        _preview_cache.pop(oldest, None)
    return result


@app.get("/api/opml/export")
async def export_opml():
    sources = DB.list_sources()
    root = ET.Element("opml", version="2.0")
    head = ET.SubElement(root, "head")
    ET.SubElement(head, "title").text = "CyberSec News Feeds"
    body = ET.SubElement(root, "body")
    for s in sources:
        ET.SubElement(
            body,
            "outline",
            text=s["name"],
            title=s["name"],
            type="rss",
            xmlUrl=s["url"],
            custom=str(bool(s["custom"])),
            enabled=str(bool(s["enabled"])),
        )
    xml_bytes = ET.tostring(root, encoding="UTF-8", xml_declaration=True)
    return Response(
        content=xml_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": 'attachment; filename="feeds.opml"'},
    )


@app.post("/api/opml/import")
async def import_opml(payload: OPMLIn):
    try:
        root = ET.fromstring(payload.opml)
    except ET.ParseError:
        raise HTTPException(status_code=400, detail="Malformed OPML")
    if root.tag != "opml":
        raise HTTPException(status_code=400, detail="Not an OPML document")
    outlines = root.findall(".//outline")[:OPML_MAX_OUTLINES]
    added, skipped = 0, 0
    for o in outlines:
        u = (o.get("xmlUrl") or "").strip()
        if not u:
            continue
        if _url_precheck(u) is not None:
            skipped += 1
            continue
        ok, _err = await _url_ssrf_check(u)
        if not ok:
            skipped += 1
            continue
        name = _sanitize_text(o.get("title") or o.get("text") or urlparse(u).hostname or u, 100) or "Imported feed"
        if DB.add_source(name, u):
            added += 1
        else:
            skipped += 1
    return {"added": added, "skipped": skipped}


@app.get("/api/export")
async def export_history():
    rows = DB.all_articles(EXPORT_LIMIT)
    payload = {"exported_at": _utcnow(), "count": len(rows), "articles": [dict(r) for r in rows]}
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": 'attachment; filename="history.json"'},
    )


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "ts": _utcnow()}


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Ctext y='13' font-size='13'%3E🛡%3C/text%3E%3C/svg%3E">
<title>CyberSec News Aggregator</title>
<style nonce="__NONCE__">
:root{--bg:#0b0f14;--card:#12181f;--border:#1e2a36;--text:#e6edf3;--muted:#8b9bab;--accent:#3b82f6;--ok:#22c55e;--err:#ef4444}
*{box-sizing:border-box;margin:0;padding:0}
[hidden]{display:none!important}
body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;min-height:100vh}
header{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;background:linear-gradient(180deg,#0f1419,var(--bg))}
.brand{display:flex;align-items:center;gap:.75rem}
h1{font-size:1.35rem;font-weight:600;letter-spacing:-.02em}
.badge{font-size:.7rem;padding:.2rem .55rem;border-radius:999px;background:#1e3a5f;color:#93c5fd}
main{max-width:1200px;margin:0 auto;padding:1.5rem}
.controls{display:flex;gap:.6rem;margin-bottom:1rem;flex-wrap:wrap;align-items:center}
button{background:var(--accent);color:#fff;border:none;padding:.55rem 1.1rem;border-radius:.5rem;font-weight:500;cursor:pointer;font-size:.9rem}
button:hover{filter:brightness(1.1)}
button:disabled{opacity:.5;cursor:not-allowed}
.btn.ghost{background:#161e27;color:var(--text);border:1px solid var(--border)}
.btn.ghost.on{background:#1e3a5f;color:#93c5fd;border-color:#2b4a77}
.btn.mini{padding:.25rem .6rem;font-size:.75rem}
.mini-act{background:none;color:var(--muted);font-size:.72rem;font-weight:400;padding:.1rem .35rem;border-radius:.3rem}
.mini-act:hover{color:var(--accent);background:#161e27;filter:none}
.status{font-size:.85rem;color:var(--muted)}
.search{flex:1;min-width:180px;background:#0f151c;border:1px solid var(--border);color:var(--text);padding:.5rem .7rem;border-radius:.5rem;font-size:.85rem}
.sel{background:#0f151c;border:1px solid var(--border);color:var(--text);padding:.45rem .5rem;border-radius:.5rem;font-size:.85rem}
.inp{background:#0f151c;border:1px solid var(--border);color:var(--text);padding:.5rem .7rem;border-radius:.5rem;font-size:.85rem}
.inp.grow{flex:1;min-width:240px}
.chips{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:1rem}
.chip{background:#10161d;border:1px solid var(--border);color:var(--muted);padding:.25rem .7rem;border-radius:999px;font-size:.75rem}
.chip.on{background:#1e3a5f;color:#93c5fd;border-color:#2b4a77}
.sources{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}
.src{display:inline-flex;align-items:center;gap:.4rem;background:#10161d;border:1px solid var(--border);padding:.3rem .6rem;border-radius:.5rem;font-size:.8rem;cursor:pointer}
.src.off{opacity:.45}
.src .x{background:none;color:var(--err);font-size:.9rem;padding:0 .2rem}
.addform{display:flex;gap:.5rem;margin-bottom:1.25rem;flex-wrap:wrap}
.banner{background:#3b1d1d;border:1px solid #7f2c2c;color:#fecaca;padding:.6rem .9rem;border-radius:.5rem;margin-bottom:1rem;font-size:.85rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1.25rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:.75rem;overflow:hidden;display:flex;flex-direction:column}
.card-header{padding:.9rem 1rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;background:#0f151c;gap:.5rem}
.card-header h2{font-size:1rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hactions{display:flex;gap:.4rem;align-items:center}
.srcmeta{font-size:.7rem;color:var(--muted);padding:.35rem 1rem 0}
.card-body{padding:.5rem 0;flex:1;max-height:460px;overflow-y:auto}
.item{padding:.75rem 1rem;border-bottom:1px solid var(--border);transition:background .15s}
.item:last-child{border-bottom:none}
.item:hover{background:#161e27}
.item.read{opacity:.45}
.item.sel{outline:1px solid var(--accent);outline-offset:-1px}
.item a{color:var(--text);text-decoration:none;font-weight:500;font-size:.92rem;display:block}
.item a:hover{color:var(--accent)}
.meta{font-size:.75rem;color:var(--muted);margin-top:.25rem}
.badge-new{display:inline-block;background:#14532d;color:#86efac;font-size:.65rem;padding:.05rem .4rem;border-radius:.3rem;margin-right:.35rem}
.summary{font-size:.8rem;color:var(--muted);margin-top:.35rem;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.cves{display:flex;gap:.35rem;flex-wrap:wrap;margin-top:.4rem}
.cve{display:inline-flex;gap:.4rem;align-items:center;background:#1a1206;border:1px solid #7c5d1a;color:#fbbf24;font-size:.7rem;padding:.1rem .45rem;border-radius:.35rem;font-family:ui-monospace,monospace}
.cve a{color:#93c5fd;text-decoration:none}
.cve a:hover{text-decoration:underline}
.actions{display:flex;gap:.15rem;margin-top:.4rem;flex-wrap:wrap}
.error{color:var(--err);font-size:.85rem;padding:1rem}
.empty{color:var(--muted);font-size:.85rem;padding:1rem;text-align:center}
.emptyAll{grid-column:1/-1}
footer{text-align:center;padding:2rem 1rem;color:var(--muted);font-size:.8rem;border-top:1px solid var(--border);margin-top:2rem}
.spinner{display:inline-block;width:1rem;height:1rem;border:2px solid #334155;border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;margin-right:.4rem;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.modal{position:fixed;inset:0;background:rgba(3,6,10,.7);display:flex;align-items:center;justify-content:center;z-index:50;padding:1rem}
.modal-card{background:var(--card);border:1px solid var(--border);border-radius:.75rem;max-width:760px;width:100%;max-height:80vh;display:flex;flex-direction:column}
.modal-head{display:flex;justify-content:space-between;align-items:center;padding:.8rem 1rem;border-bottom:1px solid var(--border);gap:1rem}
.modal-head h3{font-size:.95rem;font-weight:600}
.modal-body{padding:1rem;overflow:auto;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,monospace;font-size:.8rem}
.filelabel{position:relative;overflow:hidden;display:inline-flex;align-items:center}
.filelabel input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
</style>
</head>
<body>
<header>
<div class="brand">
<h1>CyberSec News Aggregator</h1>
<span class="badge">Local</span>
</div>
<div class="status" id="status">Ready</div>
</header>
<main>
<div class="controls">
<button id="refreshBtn" class="btn">Refresh</button>
<button id="openUnreadBtn" class="btn ghost">Open all unread</button>
<button id="unreadFilterBtn" class="btn ghost">Unread</button>
<button id="starFilterBtn" class="btn ghost">Starred</button>
<button id="exportBtn" class="btn ghost">Export JSON</button>
<button id="exportOpmlBtn" class="btn ghost">Export OPML</button>
<label class="btn ghost filelabel">Import OPML<input type="file" id="opmlFile" accept=".opml,.xml"></label>
<select id="intervalSel" class="sel" aria-label="Auto refresh interval">
<option value="0">Auto: off</option>
<option value="1">1 min</option>
<option value="5">5 min</option>
<option value="15">15 min</option>
<option value="30">30 min</option>
</select>
<input id="searchBox" class="search" type="search" placeholder="Search…  ( / )" maxlength="200" autocomplete="off">
<span class="status" id="lastUpdate"></span>
</div>
<div class="chips" id="chips"></div>
<div class="sources" id="sourcesBar"></div>
<div class="addform">
<input id="newName" class="inp" type="text" placeholder="Feed name" maxlength="100">
<input id="newUrl" class="inp grow" type="url" placeholder="https://example.com/feed.xml" maxlength="2000">
<button id="addBtn" class="btn">Add feed</button>
</div>
<div class="banner" id="banner" hidden></div>
<div class="grid" id="grid"></div>
</main>
<div class="modal" id="modal" hidden>
<div class="modal-card">
<div class="modal-head"><h3 id="modalTitle"></h3><button id="modalClose" class="btn ghost mini">Close</button></div>
<pre class="modal-body" id="modalBody"></pre>
</div>
</div>
<footer>Local-only aggregator · Read state and bookmarks stay in your browser · Sources and history in local SQLite</footer>
<script nonce="__NONCE__">
const $=function(id){return document.getElementById(id)};
const grid=$('grid'),statusEl=$('status'),lastEl=$('lastUpdate'),bannerEl=$('banner');
let S={items:[],cfg:[],filter:'',search:'',unreadOnly:false,starredOnly:false,lastVisitTs:0,current:-1,timer:null,loading:false};
let READ=new Set(loadSet('cn_read'));
let STAR=new Set(loadSet('cn_star'));
function lsGet(k){try{return localStorage.getItem(k)}catch(e){return null}}
function lsSet(k,v){try{localStorage.setItem(k,v)}catch(e){}}
function loadSet(k){try{const v=JSON.parse(lsGet(k)||'[]');return Array.isArray(v)?v.filter(function(x){return typeof x==='string'}).slice(-2000):[]}catch(e){return[]}}
function saveSet(k,set){lsSet(k,JSON.stringify(Array.from(set).slice(-2000)))}
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!=null)n.textContent=text;return n}
function esc(s){const d=document.createElement('div');d.textContent=String(s==null?'':s);return d.innerHTML}
function fmtDate(s){const t=Date.parse(s);return isNaN(t)?s:new Date(t).toLocaleString()}
S.lastVisitTs=parseInt(lsGet('cn_last_visit')||'0',10)||0;
function stampVisit(){lsSet('cn_last_visit',String(Date.now()))}
function showBanner(msg){bannerEl.textContent=msg;bannerEl.hidden=false}
async function api(path,opts){
opts=opts||{};
const h=Object.assign({'Accept':'application/json'},opts.headers||{});
if(opts.body)h['Content-Type']='application/json';
h['X-Requested-With']='XMLHttpRequest';
const r=await fetch(path,{method:opts.method||'GET',headers:h,body:opts.body,credentials:'same-origin'});
if(!r.ok){let d='';try{d=(await r.json()).detail||''}catch(e){}const err=new Error(d||('HTTP '+r.status));err.status=r.status;throw err}
const ct=r.headers.get('content-type')||'';
return ct.indexOf('json')>=0?r.json():r.text();
}
const TERMS=['ransomware','zero-day','cve','apt','supply-chain','malware','breach','exploit'];
function renderChips(){
const c=$('chips');c.innerHTML='';
TERMS.forEach(function(t){
const b=el('button','chip'+(S.filter===t?' on':''),t);
b.type='button';
b.onclick=function(){S.filter=S.filter===t?'':t;renderChips();loadFeeds(false)};
c.appendChild(b);
});
}
async function loadSources(){
try{S.cfg=await api('/api/sources');renderSources()}catch(e){renderSources()}
}
function renderSources(){
const bar=$('sourcesBar');bar.innerHTML='';
(S.cfg||[]).forEach(function(s){
const w=el('label','src'+(s.enabled?'':' off'));
const cb=document.createElement('input');cb.type='checkbox';cb.checked=!!s.enabled;
cb.onchange=function(){toggleSource(s.id,cb.checked)};
const nm=el('span',null,s.name);nm.title=s.url;
w.appendChild(cb);w.appendChild(nm);
if(s.custom){const del=el('button','x','×');del.type='button';del.title='Remove feed';del.onclick=function(e){e.preventDefault();deleteSource(s.id)};w.appendChild(del)}
bar.appendChild(w);
});
}
async function toggleSource(id,en){
try{await api('/api/sources/'+id,{method:'PATCH',body:JSON.stringify({enabled:en})})}catch(e){statusEl.textContent='Toggle failed'}
loadSources();loadFeeds(true);
}
async function deleteSource(id){
try{await api('/api/sources/'+id,{method:'DELETE'})}catch(e){statusEl.textContent='Remove failed'}
loadSources();loadFeeds(true);
}
async function addSource(){
const name=$('newName').value.trim(),url=$('newUrl').value.trim();
if(!name||!url){statusEl.textContent='Name and URL required';return}
try{
await api('/api/sources',{method:'POST',body:JSON.stringify({name:name,url:url})});
 $('newName').value='';$('newUrl').value='';
statusEl.textContent='Feed added';
loadSources();loadFeeds(true);
}catch(e){statusEl.textContent='Could not add feed (invalid, duplicate, or blocked URL)'}
}
async function loadFeeds(force){
if(S.loading)return;
S.loading=true;$('refreshBtn').disabled=true;
statusEl.innerHTML='<span class="spinner"></span>Fetching…';
try{
const q=new URLSearchParams();
if(S.filter)q.set('filter',S.filter);
if(force)q.set('refresh','true');
let data;
try{
data=await api('/api/feeds'+(q.toString()?'?'+q.toString():''));
lsSet('cn_snapshot',JSON.stringify({ts:Date.now(),data:data}));
bannerEl.hidden=true;
}catch(err){
const snap=lsGet('cn_snapshot');
if(snap){data=JSON.parse(snap).data;(data||[]).forEach(function(s){s.stale=true});showBanner('Offline — showing last saved snapshot')}
else{showBanner('Unable to load feeds');data=[]}
}
S.items=[];
(data||[]).forEach(function(src){
(src.headlines||[]).forEach(function(h){
S.items.push({title:h.title,link:h.link,published:h.published,summary:h.summary,source:h.source,first_seen:h.first_seen,srcUrl:src.url||'',fetched_at:src.fetched_at||'',stale:!!src.stale});
});
});
render();
const newCount=S.items.filter(function(i){return i.first_seen&&Date.parse(i.first_seen)>S.lastVisitTs}).length;
lastEl.textContent='Last refresh: '+new Date().toLocaleTimeString()+(S.filter?' · filter: '+S.filter:'')+(newCount?(' · '+newCount+' new since last visit'):'');
statusEl.textContent='Updated';
stampVisit();
}catch(e){statusEl.textContent='Error loading feeds'}
finally{S.loading=false;$('refreshBtn').disabled=false}
}
function visibleItems(){
const q=S.search.toLowerCase();
return S.items.filter(function(i){
if(S.unreadOnly&&READ.has(i.link))return false;
if(S.starredOnly&&!STAR.has(i.link))return false;
if(q){const hay=(i.title+' '+(i.summary||'')).toLowerCase();if(hay.indexOf(q)<0)return false}
return true;
});
}
function render(){
const vis=visibleItems();
grid.innerHTML='';
const bySource=new Map();
vis.forEach(function(i){
if(!bySource.has(i.source))bySource.set(i.source,[]);
bySource.get(i.source).push(i);
});
if(!bySource.size){grid.innerHTML='';grid.appendChild(el('div','empty emptyAll','No headlines match the current filters.'));S.current=-1;return}
bySource.forEach(function(items,name){grid.appendChild(sourceCard(name,items))});
S.current=-1;
}
function renderPreserve(){const y=window.scrollY;render();window.scrollTo(0,y)}
function sourceCard(name,items){
const card=el('div','card');
const head=el('div','card-header');
head.appendChild(el('h2',null,name));
const right=el('div','hactions');
const srcUrl=(items[0]&&items[0].srcUrl)||'';
const more=el('button','btn mini ghost','More');
more.type='button';
more.title='Load older items from local history';
more.onclick=function(){loadMore(name,srcUrl,more)};
right.appendChild(more);
head.appendChild(right);
card.appendChild(head);
const fetched=items.map(function(i){return i.fetched_at}).filter(Boolean)[0];
if(fetched)card.appendChild(el('div','srcmeta','Updated '+fmtDate(fetched)));
const body=el('div','card-body');
if(items.length){items.forEach(function(i){body.appendChild(itemRow(i))})}
else{body.appendChild(el('div','empty','No headlines'))}
card.appendChild(body);
return card;
}
function actBtn(label,title,fn){const b=el('button','mini-act',label);b.type='button';b.title=title;b.onclick=fn;return b}
function cveList(it){
const set=new Set();
const hay=it.title+' '+(it.summary||'');
const re=/CVE-\d{4}-\d{4,7}/gi;
let m;
while((m=re.exec(hay))&&set.size<6){set.add(m[0].toUpperCase())}
return Array.from(set);
}
function cveChip(id){
const w=el('span','cve');
w.appendChild(el('b',null,id));
const nvd=el('a',null,'NVD');
nvd.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(id);
nvd.target='_blank';nvd.rel='noopener noreferrer nofollow';
const mit=el('a',null,'MITRE');
mit.href='https://www.cve.org/CVERecord?id='+encodeURIComponent(id);
mit.target='_blank';mit.rel='noopener noreferrer nofollow';
w.appendChild(nvd);w.appendChild(mit);
return w;
}
function itemRow(it){
const row=el('div','item');
row.dataset.link=it.link;
if(READ.has(it.link))row.classList.add('read');
const a=el('a',null,it.title);
a.href=it.link;a.target='_blank';a.rel='noopener noreferrer nofollow';
a.onclick=function(){markReadLocal(it.link);row.classList.add('read')};
row.appendChild(a);
const meta=el('div','meta');
if(it.first_seen&&Date.parse(it.first_seen)>S.lastVisitTs)meta.appendChild(el('span','badge-new','NEW'));
const parts=[];
if(it.published)parts.push(fmtDate(it.published));
if(it.stale)parts.push('cached');
if(parts.length)meta.appendChild(document.createTextNode(parts.join(' · ')));
row.appendChild(meta);
if(it.summary)row.appendChild(el('div','summary',it.summary));
const cves=cveList(it);
if(cves.length){const cw=el('div','cves');cves.forEach(function(c){cw.appendChild(cveChip(c))});row.appendChild(cw)}
const actions=el('div','actions');
const starB=actBtn(STAR.has(it.link)?'★ Starred':'☆ Star','Toggle bookmark',function(){
toggleStarLocal(it.link);
starB.textContent=STAR.has(it.link)?'★ Starred':'☆ Star';
});
starB.classList.add('act-star');
actions.appendChild(starB);
const readB=actBtn(READ.has(it.link)?'Mark unread':'Mark read','Toggle read state',function(){
toggleReadLocal(it.link);
row.classList.toggle('read',READ.has(it.link));
readB.textContent=READ.has(it.link)?'Mark unread':'Mark read';
});
actions.appendChild(readB);
actions.appendChild(actBtn('Preview','Read clean text preview',function(){openPreview(it)}));
actions.appendChild(actBtn('Copy link','Copy article link',function(){copyLink(it.link)}));
row.appendChild(actions);
return row;
}
function markReadLocal(link){READ.add(link);saveSet('cn_read',READ)}
function toggleReadLocal(link){if(READ.has(link))READ.delete(link);else READ.add(link);saveSet('cn_read',READ)}
function toggleStarLocal(link){if(STAR.has(link))STAR.delete(link);else STAR.add(link);saveSet('cn_star',STAR)}
async function copyLink(link){
try{await navigator.clipboard.writeText(link);statusEl.textContent='Link copied'}
catch(e){
const ta=document.createElement('textarea');ta.value=link;document.body.appendChild(ta);ta.select();
try{document.execCommand('copy');statusEl.textContent='Link copied'}catch(e2){statusEl.textContent='Copy failed'}
ta.remove();
}
}
function openAllUnread(){
const un=visibleItems().filter(function(i){return !READ.has(i.link)}).slice(0,10);
if(!un.length){statusEl.textContent='No unread items';return}
un.forEach(function(i){window.open(i.link,'_blank','noopener');markReadLocal(i.link)});
statusEl.textContent='Opened '+un.length+' tab(s) — the browser may block popups';
renderPreserve();
}
async function openPreview(it){
showModal(it.title,'Loading preview…');
try{
const d=await api('/api/preview?url='+encodeURIComponent(it.link));
showModal(d.title||it.title,d.text||'(No extractable content)');
}catch(e){showModal(it.title,'Preview unavailable for this article.')}
}
function showModal(t,body){$('modalTitle').textContent=t;$('modalBody').textContent=body;$('modal').hidden=false}
function closeModal(){$('modal').hidden=true;$('modalBody').textContent=''}
async function loadMore(name,srcUrl,btn){
if(!srcUrl){btn.textContent='N/A';return}
btn.disabled=true;btn.textContent='…';
try{
const offset=S.items.filter(function(i){return i.source===name}).length;
const q=new URLSearchParams({source:srcUrl,offset:String(offset),limit:'15'});
if(S.filter)q.set('filter',S.filter);
const rows=await api('/api/history?'+q.toString());
const have=new Set(S.items.map(function(i){return i.link}));
let added=0;
rows.forEach(function(r){
if(!have.has(r.link)){
S.items.push({title:r.title,link:r.link,published:r.published,summary:r.summary,source:r.source,first_seen:r.first_seen,srcUrl:srcUrl,fetched_at:'',stale:true});
added++;
}
});
renderPreserve();
btn.textContent=added?('+'+added+' older'):'No more';
btn.disabled=false;
}catch(e){btn.textContent='Failed';btn.disabled=false}
}
function downloadBlob(blob,name){
const u=URL.createObjectURL(blob);
const a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();
setTimeout(function(){URL.revokeObjectURL(u)},2000);
}
function exportJSON(){
const payload={exported_at:new Date().toISOString(),filter:S.filter||null,count:S.items.length,articles:S.items};
downloadBlob(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}),'headlines-'+Date.now()+'.json');
statusEl.textContent='Exported '+S.items.length+' headlines';
}
function setAuto(){
const v=$('intervalSel').value;
lsSet('cn_interval',v);
if(S.timer){clearInterval(S.timer);S.timer=null}
const m=parseInt(v,10);
if(m>=1&&m<=30)S.timer=setInterval(function(){loadFeeds(false)},m*60000);
}
document.addEventListener('keydown',function(e){
if(e.ctrlKey||e.metaKey||e.altKey)return;
const tag=(e.target.tagName||'').toLowerCase();
if(tag==='input'||tag==='textarea'||tag==='select'){if(e.key==='Escape')e.target.blur();return}
if(!$('modal').hidden){if(e.key==='Escape')closeModal();return}
if(e.key==='/'){e.preventDefault();$('searchBox').focus();return}
if(e.key==='r'){loadFeeds(true);return}
const rows=Array.prototype.slice.call(grid.querySelectorAll('.item'));
if(!rows.length)return;
if(e.key==='j'||e.key==='k'){
e.preventDefault();
S.current=e.key==='j'?Math.min(S.current+1,rows.length-1):Math.max(S.current-1,0);
rows.forEach(function(r,i){r.classList.toggle('sel',i===S.current)});
rows[S.current].scrollIntoView({block:'center'});
return;
}
if(e.key==='o'&&S.current>=0){
const row=rows[S.current],link=row.dataset.link;
markReadLocal(link);row.classList.add('read');
window.open(link,'_blank','noopener');
return;
}
if(e.key==='b'&&S.current>=0){
const link=rows[S.current].dataset.link;
toggleStarLocal(link);
const sb=rows[S.current].querySelector('.act-star');
if(sb)sb.textContent=STAR.has(link)?'★ Starred':'☆ Star';
return;
}
if(e.key==='m'&&S.current>=0){
const link=rows[S.current].dataset.link;
toggleReadLocal(link);
rows[S.current].classList.toggle('read',READ.has(link));
return;
}
});
let searchT=null;
 $('searchBox').addEventListener('input',function(e){
clearTimeout(searchT);
searchT=setTimeout(function(){S.search=e.target.value.trim();renderPreserve()},250);
});
 $('unreadFilterBtn').onclick=function(e){S.unreadOnly=!S.unreadOnly;e.target.classList.toggle('on',S.unreadOnly);renderPreserve()};
 $('starFilterBtn').onclick=function(e){S.starredOnly=!S.starredOnly;e.target.classList.toggle('on',S.starredOnly);renderPreserve()};
 $('refreshBtn').onclick=function(){loadFeeds(true)};
 $('addBtn').onclick=addSource;
 $('openUnreadBtn').onclick=openAllUnread;
 $('exportBtn').onclick=exportJSON;
 $('exportOpmlBtn').onclick=function(){window.location.href='/api/opml/export'};
 $('modalClose').onclick=closeModal;
 $('modal').addEventListener('click',function(e){if(e.target===$('modal'))closeModal()});
 $('opmlFile').addEventListener('change',async function(e){
const f=e.target.files&&e.target.files[0];
if(!f)return;
if(f.size>300000){statusEl.textContent='OPML file too large';e.target.value='';return}
const text=await f.text();
try{
const r=await api('/api/opml/import',{method:'POST',body:JSON.stringify({opml:text})});
statusEl.textContent='Imported '+r.added+' feed(s), skipped '+r.skipped;
loadSources();
}catch(err){statusEl.textContent='OPML import failed'}
e.target.value='';
});
renderChips();
 $('intervalSel').value=lsGet('cn_interval')||'0';
setAuto();
loadSources();
loadFeeds(false);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    nonce = secrets.token_urlsafe(24)
    html = HTML_PAGE.replace("__NONCE__", nonce)
    resp = HTMLResponse(content=html)
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-src 'none'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    return resp


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"detail": "Invalid request parameters"})


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse(status_code=exc.status_code, content={"detail": detail})


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.error("Unhandled error type=%s path=%s", type(exc).__name__, request.url.path[:64])
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("PORT", "8000"))
    except ValueError:
        port = 8000
    if host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning("Binding to a non-localhost address increases exposure risk")
    uvicorn.run(app, host=host, port=port, log_level="info", access_log=False, server_header=False)
