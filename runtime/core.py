"""Small, fail-closed backup primitives. No credentials or customer data in logs."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request

from settings import config, controller_repo, vault_repo
CHUNK_SIZE = 512 * 1024 * 1024
MAX_BYTES = 4 * 1024 * 1024 * 1024


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def run(args, *, env=None, data=None, output=None, input_file=None):
    """Never echo stderr: pg tools can print rows, SQL and connection details."""
    result = subprocess.run(args, env=env, input=data, stdin=input_file, stdout=output or subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError("Subprocess failed: " + Path(args[0]).name)
    return result.stdout


class GitHub:
    def __init__(self, token):
        if not token:
            raise RuntimeError("Missing GitHub credential")
        self.token = token

    def call(self, path, method="GET", data=None, *, binary=False):
        url = path if path.startswith("https://") else "https://api.github.com/" + path
        if urllib.parse.urlsplit(url).hostname not in {"api.github.com", "uploads.github.com"}:
            raise RuntimeError("Invalid GitHub destination")
        body = data if binary else (json.dumps(data).encode() if data is not None else None)
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/octet-stream" if binary and method == "GET" else "application/vnd.github+json",
                   "Content-Type": "application/octet-stream" if binary else "application/json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        # urllib strips the Authorization header explicitly on asset redirects below.
        if binary and method == "GET":
            return self.download(url, headers)
        request = urllib.request.Request(url, body, headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                content = response.read()
                return json.loads(content) if content else None
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"GitHub {method} failed ({error.code})") from None

    @staticmethod
    def download(url, headers):
        class SafeRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                if urllib.parse.urlsplit(newurl).scheme != "https":
                    raise RuntimeError("Insecure asset redirect")
                redirect = super().redirect_request(req, fp, code, msg, hdrs, newurl)
                redirect.remove_header("Authorization")
                return redirect
        opener = urllib.request.build_opener(SafeRedirect())
        with opener.open(urllib.request.Request(url, headers=headers), timeout=120) as response:
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise RuntimeError("Asset exceeds safety limit")
            return data

    def pages(self, path):
        result = []
        for page in range(1, 1001):
            values = self.call(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
            result.extend(values)
            if len(values) < 100:
                return result
        raise RuntimeError("Pagination limit exceeded")

    def upload(self, release, path):
        base = release["upload_url"].split("{")[0]
        self.call(base + "?name=" + urllib.parse.quote(Path(path).name), "POST",
                  Path(path).read_bytes(), binary=True)


def guard(controller, vault):
    if os.environ.get("GITHUB_REPOSITORY") != controller_repo() or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise RuntimeError("Only the canonical main branch may use this bot")
    if os.environ.get("GITHUB_EVENT_NAME") not in {"schedule", "workflow_dispatch"}:
        raise RuntimeError("Untrusted event")
    approved = os.environ.get('BACKUP_APPROVED_SHA', '')
    if not re.fullmatch(r'[a-f0-9]{40}', approved) or os.environ.get('GITHUB_SHA') != approved:
        raise RuntimeError('This commit has not been approved for production secrets')
    repo = controller.call(f'repos/{controller_repo()}')
    if repo['private'] or repo['fork'] or repo['default_branch'] != 'main' or repo['archived']:
        raise RuntimeError('Use the dedicated public controller on main')
    branch = controller.call(f"repos/{controller_repo()}/branches/main")
    # GITHUB_TOKEN can read this flag. Full protection settings require an
    # Administration token, intentionally not requested; verify those once in UI.
    if not branch['protected']:
        raise RuntimeError('Protect the approved main branch before enabling backups')
    repo = vault.call(f"repos/{vault_repo()}")
    if repo["private"] is not True or repo["archived"]:
        raise RuntimeError("Backup vault must be private and writable")


def encrypt(directory, work, password):
    if len(password) < 32 or "\n" in password:
        raise RuntimeError("Use a single-line encryption password of at least 32 characters")
    directory, work = Path(directory), Path(work)
    manifest = {str(p.relative_to(directory)): sha(p) for p in sorted(directory.rglob("*")) if p.is_file()}
    write_json(directory / "checksums.json", manifest)
    plain = work / "bundle.tar.gz"
    with tarfile.open(plain, "w:gz") as archive:
        for path in sorted(directory.iterdir()):
            archive.add(path, arcname=path.name)
    target = work / "bundle.gpg"
    gpg_home = work / "gpg"
    gpg_home.mkdir(mode=0o700, exist_ok=True)
    run(["gpg", "--homedir", str(gpg_home), "--batch", "--pinentry-mode", "loopback",
         "--passphrase-fd", "0", "--symmetric", "--cipher-algo", "AES256", "--s2k-mode", "3",
         "--s2k-count", "65011712", "--compress-algo", "none", "--output", str(target), str(plain)],
        data=(password + "\n").encode())
    plain.unlink()
    return target


def decrypt(encrypted, destination, work, password):
    destination, work = Path(destination), Path(work)
    plain = work / "downloaded.tar.gz"
    home = work / "gpg-restore"
    home.mkdir(mode=0o700, exist_ok=True)
    run(["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback",
         "--passphrase-fd", "0", "--output", str(plain), "--decrypt", str(encrypted)],
        data=(password + "\n").encode())
    destination.mkdir(mode=0o700)
    with tarfile.open(plain, "r:gz") as archive:
        members = archive.getmembers()
        if sum(m.size for m in members) > MAX_BYTES * 4:
            raise RuntimeError("Expanded archive exceeds safety limit")
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise RuntimeError("Unsafe archive member")
        archive.extractall(destination, members=members, filter="data")
    plain.unlink()
    expected = json.loads((destination / "checksums.json").read_text())
    actual = {str(p.relative_to(destination)): sha(p) for p in destination.rglob("*")
              if p.is_file() and p != destination / "checksums.json"}
    if actual != expected:
        raise RuntimeError("Inner checksum mismatch")


def publish(vault, encrypted, work, metadata):
    if encrypted.stat().st_size > MAX_BYTES:
        raise RuntimeError("Backup exceeds 4 GiB; provision a reviewed object-store adapter")
    tag = "brote-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    release = vault.call(f"repos/{vault_repo()}/releases", "POST", {
        "tag_name": tag, "target_commitish": "main", "name": tag,
        "body": "Encrypted backup. Valid only when validation.json exists and is fresh.",
        "draft": False, "prerelease": True})
    parts = []
    with open(encrypted, "rb") as source:
        for i in range(100):
            block = source.read(CHUNK_SIZE)
            if not block:
                break
            path = Path(work) / f"bundle.gpg.part{i:03}"
            path.write_bytes(block)
            vault.upload(release, path)
            parts.append({"name": path.name, "sha256": sha(path), "bytes": len(block)})
            path.unlink()
    manifest = dict(metadata, format=1, parts=parts, sha256=sha(encrypted))
    path = Path(work) / "manifest.json"
    write_json(path, manifest)
    vault.upload(release, path)
    return release


def fetch_bundle(vault, release, work):
    assets = vault.pages(f"repos/{vault_repo()}/releases/{release['id']}/assets")
    by_name = {a["name"]: a for a in assets}
    def fetch(name):
        return vault.call(f"repos/{vault_repo()}/releases/assets/{by_name[name]['id']}", binary=True)
    manifest = json.loads(fetch("manifest.json"))
    if manifest["format"] != 1 or not 1 <= len(manifest["parts"]) <= 8:
        raise RuntimeError("Invalid backup manifest")
    encrypted = Path(work) / "downloaded.gpg"
    with open(encrypted, "wb") as output:
        for i, part in enumerate(manifest["parts"]):
            if part["name"] != f"bundle.gpg.part{i:03}":
                raise RuntimeError("Unexpected asset name")
            data = fetch(part["name"])
            if len(data) != part["bytes"] or hashlib.sha256(data).hexdigest() != part["sha256"]:
                raise RuntimeError("Encrypted asset checksum mismatch")
            output.write(data)
    if sha(encrypted) != manifest["sha256"]:
        raise RuntimeError("Encrypted bundle checksum mismatch")
    return encrypted, manifest


def retention_keep(records, current):
    """14 daily / 8 ISO weekly / 6 monthly; pre-migration 30d; pinned forever."""
    keep = set()
    valid = sorted((r for r in records if r.get("valid")), key=lambda r: r["created_at"], reverse=True)
    if valid:
        keep.add(valid[0]["id"])
    for period, limit in [(lambda d: d.date(), 14), (lambda d: d.isocalendar()[:2], 8),
                          (lambda d: (d.year, d.month), 6)]:
        seen = set()
        for record in valid:
            date = dt.datetime.fromisoformat(record["created_at"].replace("Z", "+00:00"))
            key = period(date)
            if key not in seen and len(seen) < limit:
                keep.add(record["id"])
                seen.add(key)
    for record in records:
        age = current - dt.datetime.fromisoformat(record["created_at"].replace("Z", "+00:00"))
        if record.get("pinned") or age < dt.timedelta(days=7) or (record.get("pre_migration") and age < dt.timedelta(days=30)):
            keep.add(record["id"])
    return keep
