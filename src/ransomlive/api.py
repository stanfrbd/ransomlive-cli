import os
import ssl
from pathlib import Path
from typing import TypeAlias

import httpx
from dotenv import dotenv_values

API_URL = "https://api-pro.ransomware.live"
AUTH_ENV_VAR = "RANSOMWARE_LIVE_TOKEN"

JSONValue: TypeAlias = "dict[str, JSONValue] | list[JSONValue] | str | int | float | bool | None"


class APIError(Exception):
    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def api_key(env_file: Path = Path(".env")) -> str:
    value = os.environ.get(AUTH_ENV_VAR)
    if value is None:
        try:
            with env_file.open(encoding="utf-8-sig") as stream:
                value = dotenv_values(stream=stream, interpolate=False).get(AUTH_ENV_VAR)
        except FileNotFoundError:
            pass
        except (OSError, UnicodeError):
            raise APIError("Could not read the environment file.", exit_code=2) from None
    key = (value or "").strip()
    if not key or key == "your_token_here":
        raise APIError(f"Set {AUTH_ENV_VAR} in your environment or .env file.", exit_code=2)
    if not all("!" <= char <= "~" for char in key):
        raise APIError(f"{AUTH_ENV_VAR} contains invalid characters.", exit_code=2)
    return key


def make_client(key: str, *, verify: bool = True) -> httpx.Client:
    return httpx.Client(
        base_url=API_URL,
        headers={"X-API-KEY": key, "Accept": "application/json"},
        timeout=httpx.Timeout(30.0, connect=10.0),
        verify=verify,
        follow_redirects=False,
        trust_env=False,
    )


def get_json(client: httpx.Client, path: str, params: dict[str, str]) -> JSONValue:
    try:
        response = client.get(path, params=params)
    except httpx.TimeoutException:
        raise APIError("Request to Ransomware.live timed out.") from None
    except httpx.ConnectError as error:
        pending: list[BaseException] = [error]
        seen: set[int] = set()
        while pending:
            cause = pending.pop()
            if id(cause) in seen:
                continue
            seen.add(id(cause))
            if isinstance(cause, ssl.SSLCertVerificationError):
                raise APIError(
                    "TLS certificate verification failed for Ransomware.live; "
                    "check your network's certificate configuration."
                ) from None
            pending.extend(
                nested for nested in (cause.__cause__, cause.__context__) if nested is not None
            )
        raise APIError("Could not connect to Ransomware.live.") from None
    except httpx.RequestError:
        raise APIError("Could not complete the request to Ransomware.live.") from None

    status = response.status_code
    if status in (401, 403):
        raise APIError(f"API refused access (HTTP {status}); check the key and its access.")
    if status == 404:
        raise APIError("Resource not found (HTTP 404).")
    if status == 429:
        retry = response.headers.get("Retry-After", "")
        hint = f" Wait at least {retry} seconds." if retry.isascii() and retry.isdigit() else ""
        raise APIError(f"API quota or rate limit reached (HTTP 429).{hint}", exit_code=3)
    if not response.is_success:
        raise APIError(f"Unexpected API response (HTTP {status}).")
    try:
        return response.json()
    except ValueError:
        raise APIError("API did not return valid JSON.") from None
