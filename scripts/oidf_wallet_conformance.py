#!/usr/bin/env python3

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


MODULE_ID_RE = re.compile(r"Created test module, new id:\s*([A-Za-z0-9]+)")
IMPLICIT_SUBMIT_RE = re.compile(r"xhr\.open\('POST',\s*([\"'])(.+?)\1", re.DOTALL)
TERMINAL_STATES = {"FINISHED", "INTERRUPTED"}
POLL_INTERVAL = 1.0
REQUEST_TIMEOUT = 20
SCREENSHOT_DATA_URL = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WnRk9sAAAAASUVORK5CYII="
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the official OIDF wallet runner against the local strict wallet")
    parser.add_argument("--suite-dir", required=True, help="Path to the extracted official OIDF conformance suite")
    parser.add_argument("--wallet-url", required=True, help="Base URL of the local wallet server")
    parser.add_argument("--results-dir", required=True, help="Directory for exported official runner results")
    parser.add_argument("--runner-log", required=True, help="Path for mirrored official runner stdout")
    parser.add_argument(
        "--include-alpha-unsigned",
        action="store_true",
        help="Also run the unsigned redirect_uri alpha scenario, which currently fails against strict mode because the upstream alpha plan omits the required typ header",
    )
    return parser.parse_args()


def api_request(base_url: str, token: str, method: str, path: str, body: bytes | None = None, content_type: str | None = None):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    headers = {"Authorization": f"Bearer {token}"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        data = resp.read()
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return json.loads(data.decode("utf-8"))
        return data.decode("utf-8")


def wallet_request(wallet_url: str, method: str, path: str, payload: dict | None = None):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    url = wallet_url.rstrip("/") + "/" + path.lstrip("/")
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def create_config(suite_dir: Path, results_dir: Path) -> Path:
    source = suite_dir / "scripts" / "test-configs-rp-against-op" / "vp-wallet-test-config-dcql.json"
    with source.open() as f:
        config = json.load(f)

    config["description"] = "oid4vc-dev strict wallet"
    config["client"]["dcql"] = {
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["urn:eudi:pid:de:1"],
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                ],
            }
        ]
    }

    output = results_dir / "vp-wallet-test-config-oid4vc-dev.json"
    with output.open("w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    return output


def official_runner_args(
    runner_path: Path,
    config_path: Path,
    results_dir: Path,
    include_alpha_unsigned: bool,
) -> list[str]:
    signed = (
        "oid4vp-1final-wallet-test-plan"
        "[credential_format=sd_jwt_vc]"
        "[client_id_prefix=x509_hash]"
        "[request_method=request_uri_signed]"
        "[vp_profile=plain_vp]"
        "[response_mode=direct_post]"
    )
    args = [
        sys.executable,
        str(runner_path),
        "--export-dir",
        str(results_dir),
        "--no-parallel",
        signed,
        str(config_path),
    ]
    if include_alpha_unsigned:
        redirect = (
            "oid4vp-1final-wallet-test-plan"
            "[credential_format=sd_jwt_vc]"
            "[client_id_prefix=redirect_uri]"
            "[request_method=request_uri_unsigned]"
            "[vp_profile=plain_vp]"
            "[response_mode=direct_post]"
        )
        args.extend([redirect, str(config_path)])
    return args


def reader_thread(stream, line_queue: queue.Queue[str]) -> None:
    try:
        for line in iter(stream.readline, ""):
            line_queue.put(line)
    finally:
        stream.close()


def upload_placeholder(base_url: str, token: str, module_id: str, placeholder: str) -> None:
    api_request(
        base_url,
        token,
        "POST",
        f"api/log/{module_id}/images/{placeholder}",
        body=SCREENSHOT_DATA_URL.encode("utf-8"),
        content_type="text/plain;charset=utf-8",
    )
    print(f"[monitor] uploaded screenshot placeholder for {module_id}: {placeholder}", flush=True)


def follow_redirect(redirect_uri: str) -> None:
    parsed = urllib.parse.urlsplit(redirect_uri)
    request_uri = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    req = urllib.request.Request(request_uri, method="GET")
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        body = resp.read().decode("utf-8", errors="replace")

    if not parsed.fragment:
        return

    match = IMPLICIT_SUBMIT_RE.search(body)
    if not match:
        raise RuntimeError("implicit callback page did not expose an implicitSubmitUrl")

    submit_url = match.group(2).replace("\\/", "/")
    submit_req = urllib.request.Request(
        submit_url,
        data=("#" + parsed.fragment).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain"},
    )
    with urllib.request.urlopen(submit_req, timeout=REQUEST_TIMEOUT):
        pass


def submit_wallet_request(wallet_url: str, request_url: str) -> None:
    try:
        result = wallet_request(wallet_url, "POST", "/api/presentations", {"uri": request_url})
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"[monitor] wallet rejected request {request_url}: HTTP {exc.code} {body}", flush=True)
        return

    response = result.get("response", {})
    redirect_uri = response.get("redirect_uri")
    print(f"[monitor] submitted verifier request to wallet: {request_url}", flush=True)
    if redirect_uri:
        try:
            follow_redirect(redirect_uri)
            print(f"[monitor] followed verifier redirect_uri: {redirect_uri}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[monitor] failed to follow redirect_uri {redirect_uri}: {exc}", flush=True)


def handle_module(base_url: str, token: str, wallet_url: str, module_id: str, state: dict) -> None:
    info = api_request(base_url, token, "GET", f"api/info/{module_id}")
    logs = api_request(base_url, token, "GET", f"api/log/{module_id}")

    for entry in logs:
        redirect_to = entry.get("redirect_to")
        if redirect_to and redirect_to not in state["submitted_urls"]:
            state["submitted_urls"].add(redirect_to)
            submit_wallet_request(wallet_url, redirect_to)

        placeholder = entry.get("upload")
        if placeholder and placeholder not in state["uploaded_placeholders"]:
            state["uploaded_placeholders"].add(placeholder)
            upload_placeholder(base_url, token, module_id, placeholder)

    status = info.get("status", "")
    if status in TERMINAL_STATES:
        state["terminal"] = True


def main() -> int:
    args = parse_args()
    suite_dir = Path(args.suite_dir)
    results_dir = Path(args.results_dir)
    runner_log = Path(args.runner_log)
    runner_path = suite_dir / "scripts" / "run-test-plan.py"

    base_url = os.environ["CONFORMANCE_SERVER"]
    token = os.environ["CONFORMANCE_TOKEN"]

    results_dir.mkdir(parents=True, exist_ok=True)
    config_path = create_config(suite_dir, results_dir)

    cmd = official_runner_args(runner_path, config_path, results_dir, args.include_alpha_unsigned)
    proc = subprocess.Popen(
        cmd,
        cwd=suite_dir / "scripts",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None

    line_queue: queue.Queue[str] = queue.Queue()
    thread = threading.Thread(target=reader_thread, args=(proc.stdout, line_queue), daemon=True)
    thread.start()

    module_state: dict[str, dict] = {}

    with runner_log.open("w") as log_file:
        while True:
            try:
                while True:
                    line = line_queue.get_nowait()
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    log_file.write(line)
                    log_file.flush()
                    match = MODULE_ID_RE.search(line)
                    if match:
                        module_id = match.group(1)
                        module_state.setdefault(
                            module_id,
                            {
                                "submitted_urls": set(),
                                "uploaded_placeholders": set(),
                                "terminal": False,
                            },
                        )
            except queue.Empty:
                pass

            for module_id, state in module_state.items():
                if state["terminal"]:
                    continue
                try:
                    handle_module(base_url, token, args.wallet_url, module_id, state)
                except Exception as exc:  # noqa: BLE001
                    print(f"[monitor] failed to monitor module {module_id}: {exc}", flush=True)

            if proc.poll() is not None and line_queue.empty() and not thread.is_alive():
                break

            time.sleep(POLL_INTERVAL)

    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
