#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "typer",
#   "rich",
#   "beautifulsoup4",
#   "requests",
#   "requests-ip-rotator"
# ]
# ///

"""
ctfd-enum: Enumeration tool for CTFd.

Usage:
    ./ctfd-enum.py config.yaml

License:
    MIT License (c) 2025 bjornmorten
"""

import copy
import re
import time
from contextlib import contextmanager
from itertools import chain, zip_longest
from pathlib import Path
from typing import NamedTuple, Optional

import requests
import typer
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

console = Console()
app = typer.Typer(add_completion=False)


# -------------------------
# Constants
# -------------------------

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
def create_requests_session(base_url: str, rotate: bool = False):
    session = requests.Session()
    if rotate:
        console.print(":x: Rotating IP mode has not been implemented", style="red")
        raise typer.Exit(code=2)

        """
        from requests_ip_rotator import ApiGateway

        gateway = ApiGateway(base_url)
        gateway.start()
        session.mount(base_url, gateway)
        """
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
    url = base_url.rstrip("/") + "/register"
    try:
        r = session.get(url)
        return extract_nonce_from_html(r.text)
    except Exception:
        return None


def post_register(
    session: requests.Session,
    base_url: str,
    nonce: str,
    username: str | None = None,
    email: str | None = None,
    regcode: str | None = None,
) -> requests.Response:
    if not any([username, email, regcode]):
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
    email = attempt.email or (f"@{attempt.email_domain}" if attempt.email_domain else None)
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


# -------------------------
# Enumeration entrypoints
# -------------------------
def enumerate_register(
    base_url: str,
    usernames: list[str],
    emails: list[str],
    domains: list[str],
    codes: list[str],
    rotate: bool = False,
):
    session = create_requests_session(base_url, rotate)
    nonce = fetch_nonce(session, base_url)
    attempts = build_registration_attempts(usernames, emails, domains, codes)

    # TODO: probe check if registration code and domain whitelisting is enabled

    if rotate:
        # TODO
        raise NotImplementedError("Rotating IP mode has not been implemented")
    else:
        # TODO: optimize if regcode is found and is only remaining task: break
        with Progress(
            TextColumn("[bold cyan]Enumerating[/]"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("registration", total=len(attempts))

            for attempt in attempts:
                while True:
                    try:
                        res = attempt_registration(session, base_url, nonce, attempt)
                    except RateLimitError:
                        time.sleep(RATELIMIT_PERIOD)
                        continue
                    except Exception as e:
                        console.print(f"[red]Error while testing {attempt}: {e}[/]")
                        break

                    if attempt.username and res["username"]:
                        console.print(f"[green]Found existing username:[/] {attempt.username}")
                    if attempt.email and res["email"]:
                        console.print(f"[green]Found existing email:[/] {attempt.email}")
                    if attempt.email_domain and res["email_domain"]:
                        console.print(
                            f"[green]Found whitelisted email domain:[/] {attempt.email_domain}"
                        )
                    if attempt.registration_code and res["registration_code"]:
                        console.print(
                            f"[green]Found valid registration code:[/] {attempt.registration_code}"
                        )

                    break

                progress.advance(task)


def enumerate_login(
    base_url: str,
    usernames: list[str],
    passwords: list[str],
    rotate: bool = False,
):
    session = create_requests_session(base_url, rotate)
    nonce = fetch_nonce(session, base_url)

    if rotate:
        # TODO
        raise NotImplementedError("Rotating IP mode has not been implemented")
    else:
        total_attempts = len(usernames) * len(passwords)

        with Progress(
            TextColumn("[bold cyan]Enumerating[/]"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("login", total=total_attempts)

            for u in usernames:
                found_correct_password = False

                for p in passwords:
                    if found_correct_password:
                        remaining = len(passwords) - passwords.index(p)
                        new_total = progress.tasks[0].total - remaining
                        progress.update(task, total=new_total)
                        break

                    while True:
                        try:
                            res = attempt_login(session, base_url, nonce, u, p)
                        except RateLimitError:
                            time.sleep(RATELIMIT_PERIOD)
                            continue
                        except Exception as e:
                            console.print(f"[red]Error while testing {u}:{p}: {e}[/]")
                            break

                        if res:
                            console.print(f"[green]Valid:[/] {u}:{p}")
                            found_correct_password = True

                        break

                    progress.advance(task)


# -------------------------
# CLI
# -------------------------
@app.command("register")
def register(
    target: str = typer.Argument(
        ..., help="Base URL of the CTFd instance (e.g. https://demo.ctfd.io)"
    ),
    rotate: bool = typer.Option(
        False, "-r", "--rotate-ips", help="Enable IP rotation using AWS Gateways"
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

    enumerate_register(target, usernames_list, valid_emails, valid_domains, codes_list, rotate)


@app.command("login")
def login(
    target: str = (
        typer.Argument(..., help="Base URL of the CTFd instance (e.g. https://demo.ctfd.io)")
    ),
    rotate: bool = typer.Option(
        False, "-r", "--rotate-ips", help="Enable IP rotation using AWS Gateways"
    ),
    username: str | None = (
        typer.Option(None, "-u", "--username", help="Username or email to use in bruteforce")
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

    enumerate_login(target, usernames_list, passwords_list, rotate)


if __name__ == "__main__":
    app()
