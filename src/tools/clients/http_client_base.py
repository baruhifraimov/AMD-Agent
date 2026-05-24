"""Shared HTTP client primitives: throttle, circuit breaker, retries."""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx

from src.log import PHASE_API, get_logger, phase_log, vlog

logger = get_logger(__name__)

RETRYABLE_STATUS = frozenset({502, 503, 504})
RATE_LIMIT_STATUS = 429
DEFAULT_BACKOFF_SECONDS = (10.0, 30.0, 60.0)


class ApiUnavailable(Exception):
    """Raised when an API circuit is open or the service is unavailable."""


class CircuitBreaker:
    """Consecutive-failure circuit with optional 429 handling."""

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        open_seconds: float = 120.0,
        open_seconds_429: float = 3600.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.open_seconds = open_seconds
        self.open_seconds_429 = open_seconds_429
        self._consecutive_failures = 0
        self._open_until = 0.0

    def available(self) -> bool:
        return time.monotonic() >= self._open_until

    def reset(self) -> None:
        self._consecutive_failures = 0
        self._open_until = 0.0

    def ensure_available(self) -> None:
        if not self.available():
            raise ApiUnavailable("API circuit is open")

    def record_success(self) -> None:
        self._consecutive_failures = 0

    def record_failure(self, exc: BaseException) -> None:
        if not _is_retryable_5xx(exc):
            return
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.failure_threshold:
            self._open(self.open_seconds, reason=f"{self._consecutive_failures} consecutive failures")

    def open_for_rate_limit(self) -> None:
        self._consecutive_failures = 0
        self._open(self.open_seconds_429, reason="HTTP 429 after backoff retries")

    def _open(self, seconds: float, *, reason: str) -> None:
        self._open_until = time.monotonic() + seconds
        logger.warning("[%s] API circuit open for %.0fs (%s)", PHASE_API, seconds, reason)


class RateLimiter:
    """Minimum interval between outbound requests (thread-safe)."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._last_at = 0.0

    def reset_clock(self) -> None:
        self._last_at = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last_at)
            if delay > 0:
                time.sleep(delay)
            self._last_at = time.monotonic()


def _is_retryable_5xx(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in RETRYABLE_STATUS
    return False


class HttpApiClient:
    """Base class for form/JSON HTTP APIs with throttle and circuit breaker."""

    def __init__(
        self,
        *,
        base_url: str,
        headers: dict[str, str] | None = None,
        min_request_interval: float = 0.0,
        circuit: CircuitBreaker | None = None,
        backoff_seconds: tuple[float, ...] = DEFAULT_BACKOFF_SECONDS,
        http2: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/" if not base_url.endswith("/") else base_url
        self.headers = dict(headers or {})
        self._limiter = RateLimiter(min_request_interval)
        self._circuit = circuit or CircuitBreaker()
        self._backoff_seconds = backoff_seconds
        self._http2 = http2

    @property
    def circuit(self) -> CircuitBreaker:
        return self._circuit

    @property
    def limiter(self) -> RateLimiter:
        return self._limiter

    def available(self) -> bool:
        return self._circuit.available()

    def reset_state(self) -> None:
        self._circuit.reset()
        self._limiter.reset_clock()

    def post_form(
        self,
        data: dict[str, str],
        *,
        timeout: float = 60.0,
        use_json: bool = False,
    ) -> httpx.Response:
        """POST with throttle, 429 backoff, and circuit handling."""
        self._circuit.ensure_available()
        last_exc: BaseException | None = None

        for attempt in range(len(self._backoff_seconds) + 1):
            self._limiter.wait()
            try:
                with httpx.Client(timeout=timeout, http2=self._http2) as client:
                    if use_json:
                        response = client.post(
                            self.base_url,
                            json=data,
                            headers=self.headers,
                        )
                    else:
                        response = client.post(
                            self.base_url,
                            data=data,
                            headers=self.headers,
                        )
                if response.status_code == RATE_LIMIT_STATUS:
                    if attempt < len(self._backoff_seconds):
                        delay = self._backoff_seconds[attempt]
                        vlog(
                            logger,
                            "warning",
                            "HTTP 429 on %s; backing off %.0fs (attempt %d)",
                            self.base_url,
                            delay,
                            attempt + 1,
                        )
                        time.sleep(delay)
                        continue
                    self._circuit.open_for_rate_limit()
                    raise ApiUnavailable("Rate limited (HTTP 429)") from None
                if response.status_code in RETRYABLE_STATUS:
                    status_exc = httpx.HTTPStatusError(
                        f"HTTP {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                    last_exc = status_exc
                    if attempt < len(self._backoff_seconds):
                        delay = self._backoff_seconds[attempt]
                        vlog(
                            logger,
                            "warning",
                            "HTTP %s on %s; backing off %.0fs (attempt %d)",
                            response.status_code,
                            self.base_url,
                            delay,
                            attempt + 1,
                        )
                        time.sleep(delay)
                        continue
                    self._circuit.record_failure(status_exc)
                    if not self._circuit.available():
                        raise ApiUnavailable("API circuit opened") from status_exc
                    raise status_exc
                response.raise_for_status()
                self._circuit.record_success()
                return response
            except ApiUnavailable:
                raise
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt < len(self._backoff_seconds):
                    delay = self._backoff_seconds[attempt]
                    vlog(
                        logger,
                        "warning",
                        "Transport error on %s; backing off %.0fs (attempt %d): %s",
                        self.base_url,
                        delay,
                        attempt + 1,
                        exc,
                    )
                    time.sleep(delay)
                    continue
                self._circuit.record_failure(exc)
                if not self._circuit.available():
                    raise ApiUnavailable("API circuit opened") from exc
                raise
            except Exception as exc:
                last_exc = exc
                self._circuit.record_failure(exc)
                if not self._circuit.available():
                    raise ApiUnavailable("API circuit opened") from exc
                raise

        if last_exc is not None:
            raise last_exc
        raise ApiUnavailable("Request failed")

    def get(
        self,
        params: dict[str, Any],
        *,
        endpoint: str = "",
        timeout: float = 60.0,
    ) -> httpx.Response:
        """GET with throttle and circuit (no 429 retry loop by default)."""
        self._circuit.ensure_available()
        self._limiter.wait()
        url = self.base_url + endpoint.lstrip("/") if endpoint else self.base_url
        try:
            with httpx.Client(timeout=timeout, http2=self._http2) as client:
                response = client.get(url, params=params, headers=self.headers)
            response.raise_for_status()
            self._circuit.record_success()
            return response
        except Exception as exc:
            self._circuit.record_failure(exc)
            if not self._circuit.available():
                raise ApiUnavailable("API circuit opened") from exc
            raise
