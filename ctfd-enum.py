#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "typer",
#   "rich",
#   "colorama",
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
import time
from contextlib import contextmanager
from itertools import chain, zip_longest
from typing import NamedTuple, Optional, Callable, Any, TypeVar, List
from pathlib import Path
from typing import NamedTuple, Optional
from tqdm.rich import tqdm
from colorama import Fore, Style

from concurrent.futures import ThreadPoolExecutor, as_completed

import threading
import requests
import typer
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
import warnings
from tqdm import TqdmExperimentalWarning

warnings.filterwarnings("ignore", category=TqdmExperimentalWarning)

console = Console()
app = typer.Typer(add_completion=False)
console_lock = threading.Lock()
T = TypeVar("T")


# -------------------------
# Constants
# -------------------------

USER_AGENT = "ctfd-enum/0.1 (+https://github.com/bjornmorten/ctfd-enum)"

ERROR_PATTERNS: dict[str, tuple[str, bool]] = {
    "username": ("That user name is already taken", True),
    "email": ("That email has already been used", True),
    "email_domain": ("Your email address is not from an allowed domain", False),
    "registration_code": ("The registration code you entered was incorrect", False),
}

RATELIMIT_PERIOD = 5


# -------------------------
# Parsers / helpers
# -------------------------
def extract_nonce_from_html(html: str) -> Optional[str]:
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")

    inp = soup.find("input", {"name": "nonce"})
    if inp and inp.has_attr("value"):
        return inp["value"]


def extract_errors_from_html(html: str) -> list[str]:
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    alert_nodes = soup.select(".alert")

    msgs = [node.get_text(strip=True) for node in alert_nodes]

    return msgs


# -------------------------
# I/O helpers
# -------------------------
def load_wordlist(path: Path) -> list[str]:
    if path is None:
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = []
    seen = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line in seen:
            continue
        seen.add(line)
        lines.append(line)
    return lines


# -------------------------
# Requests session
# -------------------------
def create_requests_session(base_url: str):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


# -------------------------
# HTTP / CTFd helpers
# -------------------------
class RateLimitError(Exception):
    """Raised when the server rate-limits the client (HTTP 429)."""

    pass


@contextmanager
def preserve_cookies(session: requests.Session):
    """Ensure we don't set cookies when login is successful"""
    old_cookies = copy.deepcopy(session.cookies)
    try:
        yield
    finally:
        session.cookies = old_cookies


def fetch_nonce(session: requests.Session, base_url: str) -> str | None:
    # TODO: check if is CTFd instance?
    url = base_url.rstrip("/") + "/register"
    try:
        r = session.get(url)
        return extract_nonce_from_html(r.text)
    except Exception:
        return None


def prepare_session(base_url: str) -> tuple[requests.Session, str | None]:
    """Create a requests session and fetch the initial nonce."""
    session = create_requests_session(base_url)
    nonce = fetch_nonce(session, base_url)
    if not nonce:
        console.print("[red]Failed to fetch nonce from target[/]")
    return session, nonce


def post_register(
    session: requests.Session,
    base_url: str,
    nonce: str,
    username: str | None = None,
    email: str | None = None,
    regcode: str | None = None,
) -> requests.Response:
    if not (username or email or regcode):
        raise ValueError("Either username, email or regcode has to be set.")

    url = f"{base_url.rstrip('/')}/register"
    payload = {
        "name": username or "",
        "email": email or "",
        "password": "",
        "registration_code": regcode or "",
        "nonce": nonce,
    }
    return session.post(url, data=payload, allow_redirects=False)


def post_login(
    session: requests.Session,
    base_url: str,
    nonce: str,
    username: str,
    password: str,
) -> requests.Response:
    if not all([username, password]):
        raise ValueError("Both name and password has to be set.")

    url = f"{base_url.rstrip('/')}/login"
    payload = {"name": username, "password": password, "nonce": nonce}
    with preserve_cookies(session):
        res = session.post(url, data=payload, allow_redirects=False)
    return res


# -------------------------
# Enumeration helpers
# -------------------------
class RegistrationAttempt(NamedTuple):
    username: str | None
    email: str | None
    email_domain: str | None
    registration_code: str | None


class LoginAttempt(NamedTuple):
    username: str
    password: str


def build_registration_attempts(
    usernames: list[str],
    emails: list[str],
    domains: list[str],
    codes: list[str],
) -> list[RegistrationAttempt]:
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
) -> list[LoginAttempt]:
    attempts = [(u, p) for u in usernames for p in passwords]
    return attempts


def classify_register_response(r: requests.Response) -> dict[str, bool]:
    if r.status_code == 429:
        raise RateLimitError("Rate limit exceeded")
    errors = extract_errors_from_html(r.text)
    return {k: (v in errors) == b for k, (v, b) in ERROR_PATTERNS.items()}


def classify_login_response(r: requests.Response) -> bool:
    if r.status_code == 302:
        return True
    elif r.status_code == 429:
        raise RateLimitError("Rate limit exceeded")
    elif "Your username or password is incorrect" in r.text:
        return False

    raise Exception("Invalid response")


def attempt_registration(
    session: requests.Session, base_url: str, nonce: str, attempt: RegistrationAttempt
) -> dict[str, bool]:
    email = attempt.email or (
        f"@{attempt.email_domain}" if attempt.email_domain else None
    )
    resp = post_register(
        session, base_url, nonce, attempt.username, email, attempt.registration_code
    )
    valid = classify_register_response(resp)
    return valid


def attempt_login(
    session: requests.Session, base_url: str, nonce: str, username: str, password: str
) -> bool:
    resp = post_login(session, base_url, nonce, username, password)
    valid = classify_login_response(resp)
    return valid


def print_register_result(
    attempt: RegistrationAttempt, result: dict[str, bool]
) -> None:
    if attempt.username and result["username"]:
        console.print(f"[green]Found existing username:[/] {attempt.username}")
    if attempt.email and result["email"]:
        console.print(f"[green]Found existing email:[/] {attempt.email}")
    if attempt.email_domain and result["email_domain"]:
        console.print(
            f"[green]Found whitelisted email domain:[/] {attempt.email_domain}"
        )
    if attempt.registration_code and result["registration_code"]:
        console.print(
            f"[green]Found valid registration code:[/] {attempt.registration_code}"
        )


# -------------------------
# Enumeration orchestration
# -------------------------

from threading import Barrier

rate_limited = False


def safe_worker(
    item: T, worker: Callable[[T], Any], barrier: Barrier
) -> tuple[T, Any | Exception]:
    global rate_limited

    try:
        barrier.wait()
    except Exception:
        pass

    try:
        if rate_limited:
            raise Exception("already rate_limited")

        result = worker(item)
        return item, result, time.time()
    except RateLimitError as e:
        rate_limited = True
        return item, e, time.time()
    except Exception as e:
        print(e)
        return item, e, time.time()


from queue import Queue, Empty


def run_enumeration(
    items: list[T],
    worker: Callable[[T], Any],
    printer: Callable[[T, Any], None],
    threads: int,
):
    global rate_limited

    queue = Queue()
    batch_size = threads

    for item in items:
        queue.put(item)

    total = len(items)
    last_request_time = time.time()

    with (
        ThreadPoolExecutor(max_workers=threads) as executor,
        tqdm(total=total, desc="Enumerating") as pbar,
    ):
        while not queue.empty():
            batch = []
            for _ in range(batch_size):
                try:
                    batch.append(queue.get_nowait())
                except Empty:
                    break

            if not batch:
                break

            barrier = Barrier(min(threads, len(batch)))

            time.sleep(5.25 - (time.time() - last_request_time))
            rate_limited = False

            futures = [
                executor.submit(safe_worker, item, worker, barrier) for item in batch
            ]

            suc = 0
            err = 0
            for fut in as_completed(futures):
                item, result, request_time = fut.result()
                last_request_time = max(last_request_time, request_time)

                if isinstance(result, Exception):
                    queue.put(item)
                    err += 1
                else:
                    printer(item, result)
                    suc += 1

            pbar.update(suc)

            print(
                f"Batch finished ({len(batch)})",
                f"{suc=}, {err=} (total: {suc + err})",
            )


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
):
    attempts = build_registration_attempts(usernames, emails, domains, codes)

    def worker(attempt: RegistrationAttempt):
        session = create_requests_session(base_url)
        try:
            nonce = fetch_nonce(session, base_url)
            if not nonce:
                return None
            return attempt_registration(session, base_url, nonce, attempt)
        finally:
            try:
                session.close()
            except Exception:
                pass

    def printer(attempt: RegistrationAttempt, result: dict[str, bool]):
        print_register_result(attempt, result)

    run_enumeration(attempts, worker, printer, threads=threads)


def enumerate_login(
    base_url: str,
    usernames: list[str],
    passwords: list[str],
    threads: int,
):
    combos = build_login_attempts(usernames, passwords)
    session, nonce = prepare_session(base_url)

    def worker(pair: tuple[str, str]):
        u, p = pair
        try:
            return attempt_login(session, base_url, nonce, u, p)
        finally:
            try:
                session.close()
            except Exception:
                pass

    def printer(pair: tuple[str, str], result: bool):
        if result:
            tqdm.write(f"Valid: {pair[0]}:{pair[1]}")

    run_enumeration(combos, worker, printer, threads=threads)


# -------------------------
# CLI
# -------------------------
@app.command("register")
def register(
    target: str = typer.Argument(
        ..., help="Base URL of the CTFd instance (e.g. https://demo.ctfd.io)"
    ),
    threads: int = typer.Option(
        20,
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
):
    """
    Enumerate CTFd registration (usernames, emails, registration codes).
    """
    usernames_list = load_wordlist(usernames) if usernames else []
    emails_list = load_wordlist(emails) if emails else []
    domains_list = load_wordlist(domains) if domains else []
    codes_list = load_wordlist(codes) if codes else []

    # Check if emails and email domains are valid
    valid_emails = [e for e in emails_list if "@" in e]
    invalid_emails = [e for e in emails_list if "@" not in e]

    valid_domains = [d for d in domains_list if "@" not in d]
    invalid_domains = [d for d in domains_list if "@" in d]

    if invalid_emails:
        console.print(
            f"[yellow]Warning:[/] {len(invalid_emails)} invalid email(s) removed (missing '@')"
        )

    if invalid_domains:
        console.print(
            f"[yellow]Warning:[/] {len(invalid_domains)} invalid domain(s) removed (contain '@')"
        )

    if not (usernames_list or valid_emails or valid_domains or codes_list):
        typer.secho(
            "Nothing to enumerate: provide at least one of --usernames, --emails, --domains or --codes.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    console.print(f"[bold cyan]Starting registration enumeration against {target}[/]")

    enumerate_register(
        target, usernames_list, valid_emails, valid_domains, codes_list, threads
    )


@app.command("login")
def login(
    target: str = (
        typer.Argument(
            ..., help="Base URL of the CTFd instance (e.g. https://demo.ctfd.io)"
        )
    ),
    threads: int = typer.Option(
        20,
        "-t",
        "--threads",
        help="Number of threads",
    ),
    username: str | None = (
        typer.Option(
            None, "-u", "--username", help="Username or email to use in bruteforce"
        )
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
    password: str | None = (
        typer.Option(None, "-p", "--password", help="Password to use in bruteforce")
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
):
    """
    Bruteforces CTFd login with provided usernames and passwords.
    """
    if bool(username) == bool(usernames):
        typer.secho(
            "Error: supply exactly one of -u/--username OR -U/--usernames",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    if bool(password) == bool(passwords):
        typer.secho(
            "Error: supply exactly one of -p/--password OR -P/--passwords",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    usernames_list = [username] if username else load_wordlist(usernames)
    passwords_list = [password] if password else load_wordlist(passwords)

    console.print(f"[bold cyan]Starting login enumeration against {target}[/]")

    enumerate_login(target, usernames_list, passwords_list, threads)


if __name__ == "__main__":
    app()
