"""
Shared async HTTP layer: retries with exponential backoff (via tenacity),
a sliding-window rate limiter (used by the NVD downloader to respect its
5-or-50-requests-per-30s limit), and streaming file downloads that compute
a sha256 while writing to disk (no second read pass needed for checksums).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import httpx
from tenacity import AsyncRetrying, RetryError, stop_after_attempt, wait_exponential

from config.config_schema import RetryConfig
from scripts.common.logging_utils import get_logger

logger = get_logger(__name__, category="download")

DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=30.0, pool=10.0)
USER_AGENT = "vuln-survival-pipeline/0.1 (capstone research; contact via project repo)"


class DownloadError(RuntimeError):
    pass


@dataclass
class DownloadResult:
    byte_size: int
    sha256: str
    http_status: int


class SlidingWindowRateLimiter:
    """Blocks `acquire()` calls so no more than `max_requests` occur within
    any rolling `window_seconds` window. Shared across all requests to one
    source within a single process."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            while self._timestamps and now - self._timestamps[0] > self.window_seconds:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.max_requests:
                sleep_for = self.window_seconds - (now - self._timestamps[0])
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] > self.window_seconds:
                    self._timestamps.popleft()
            self._timestamps.append(time.monotonic())


def _retrying(retry_cfg: RetryConfig) -> AsyncRetrying:
    # reraise=False (the default) is required, not cosmetic: on final failure
    # this makes tenacity raise RetryError, which is what fetch_json/
    # download_file's `except RetryError` below is written to catch and
    # convert into DownloadError. With reraise=True, tenacity instead
    # re-raises the original exception (e.g. httpx.ConnectTimeout) directly —
    # DownloadError is never raised, callers that catch DownloadError never
    # see it, and one exhausted-retries host hiccup crashes the whole
    # process instead of being recorded as a single failed/skipped item.
    return AsyncRetrying(
        stop=stop_after_attempt(retry_cfg.max_attempts),
        wait=wait_exponential(
            multiplier=retry_cfg.backoff_base_seconds,
            max=retry_cfg.backoff_max_seconds,
        ),
    )


async def fetch_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    retry_cfg: RetryConfig,
    rate_limiter: SlidingWindowRateLimiter | None = None,
) -> dict:
    async def _do() -> dict:
        if rate_limiter:
            await rate_limiter.acquire()
        resp = await client.get(url, params=params, headers=headers, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    try:
        async for attempt in _retrying(retry_cfg):
            with attempt:
                return await _do()
    except RetryError as e:
        raise DownloadError(f"GET {url} failed after {retry_cfg.max_attempts} attempts") from e
    raise DownloadError(f"GET {url} failed unexpectedly")  # pragma: no cover — unreachable


async def download_file(
    client: httpx.AsyncClient,
    url: str,
    dest_path: Path,
    *,
    retry_cfg: RetryConfig,
    rate_limiter: SlidingWindowRateLimiter | None = None,
    headers: dict | None = None,
) -> DownloadResult:
    """Streams `url` to `dest_path`, computing sha256 as it writes. On
    retry, always restarts the stream from scratch (safe — these sources
    serve small-to-medium immutable files, not multi-GB archives, so partial
    -range resume isn't worth the complexity)."""

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    async def _do() -> DownloadResult:
        if rate_limiter:
            await rate_limiter.acquire()
        digest = hashlib.sha256()
        byte_count = 0
        tmp_path = dest_path.with_suffix(dest_path.suffix + ".part")
        async with client.stream("GET", url, headers=headers, timeout=DEFAULT_TIMEOUT) as resp:
            resp.raise_for_status()
            with tmp_path.open("wb") as f:
                async for chunk in resp.aiter_bytes(chunk_size=1024 * 256):
                    f.write(chunk)
                    digest.update(chunk)
                    byte_count += len(chunk)
            http_status = resp.status_code
        tmp_path.replace(dest_path)
        return DownloadResult(byte_size=byte_count, sha256=digest.hexdigest(), http_status=http_status)

    try:
        async for attempt in _retrying(retry_cfg):
            with attempt:
                return await _do()
    except RetryError as e:
        raise DownloadError(f"GET {url} -> {dest_path} failed after {retry_cfg.max_attempts} attempts") from e
    raise DownloadError(f"GET {url} failed unexpectedly")  # pragma: no cover — unreachable


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, follow_redirects=True)
