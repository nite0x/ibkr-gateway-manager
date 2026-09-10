#!/usr/bin/env python3
"""Exercise an image in isolated HTTP and HTTPS containers, without account login."""
import argparse
from http.cookies import SimpleCookie
import json
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.request


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def check_image(image, tls, install):
    name = "ibkr-smoke-" + secrets.token_hex(5)
    password = secrets.token_urlsafe(32)
    scheme = "https" if tls else "http"
    origin = scheme + "://manager.localhost:8088"
    env = {
        "IBKR_GATEWAY_MANAGER_USERNAME": "smoke",
        "IBKR_GATEWAY_MANAGER_PASSWORD": password,
        "IBKR_GATEWAY_MANAGER_LISTEN": "0.0.0.0:8088",
        "IBKR_GATEWAY_MANAGER_PUBLIC_URL": origin,
    }
    if tls:
        env["IBKR_GATEWAY_LOCAL_TLS"] = "true"
    args = ["run", "-d", "--name", name, "--init", "--publish", "127.0.0.1::8088",
            "--tmpfs", "/home/gateway/.config/ibkr-gateway-manager:uid=10001,gid=10001,mode=0700"]
    for key, value in env.items():
        args.extend(["--env", key + "=" + value])
    args.append(image)
    started = False
    try:
        docker(*args)
        started = True
        port = docker("port", name, "8088/tcp").rsplit(":", 1)[1]
        context = None
        if tls:
            for _ in range(60):
                ca = subprocess.run(
                    ["docker", "exec", name, "cat", "/home/gateway/.config/ibkr-gateway-manager/tls/ca.crt"],
                    capture_output=True, text=True,
                )
                if ca.returncode == 0:
                    context = ssl.create_default_context(cadata=ca.stdout)
                    break
                time.sleep(0.5)
            if context is None:
                raise RuntimeError("local CA was not created")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context),
        )

        def request(method, path, body=None, cookie=None, expected=200, request_origin=origin):
            headers = {"Host": "manager.localhost:8088", "Origin": request_origin}
            if cookie:
                headers["Cookie"] = cookie
            payload = None
            if body is not None:
                headers["Content-Type"] = "application/json"
                payload = json.dumps(body).encode()
            req = urllib.request.Request(
                f"{scheme}://127.0.0.1:{port}{path}", payload, headers, method=method,
            )
            try:
                response = opener.open(req, timeout=180 if install else 10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                if response.status != expected:
                    error = json.loads(data) if response.headers.get("Content-Type", "").startswith("application/json") else {}
                    detail = str(error.get("details", error.get("error", ""))).replace(password, "[redacted]")
                    raise RuntimeError(f"{method} {path}: HTTP {response.status}, expected {expected}: {detail}")
                return response.headers, data

        for attempt in range(60):
            try:
                request("GET", "/healthz")
                break
            except (OSError, RuntimeError):
                if attempt == 59:
                    raise
                time.sleep(0.5)
        request("GET", "/manager/")
        request("GET", "/management/v1/gateways", expected=401)
        credentials = {"username": "smoke", "password": password}
        request("POST", "/auth/v1/session", credentials, expected=403, request_origin="https://untrusted.example")
        headers, _ = request("POST", "/auth/v1/session", credentials)
        cookies = SimpleCookie()
        cookies.load(headers["Set-Cookie"])
        session = next(iter(cookies.values()))
        if not session["httponly"] or bool(session["secure"]) != tls:
            raise RuntimeError("incorrect session cookie security attributes")
        cookie = session.key + "=" + session.value
        _, body = request("GET", "/management/v1/gateways", cookie=cookie)
        if json.loads(body)["gateways"] != []:
            raise RuntimeError("fresh image unexpectedly contains Gateway instances")
        request("PUT", "/management/v1/config", {
            "gateways": {"primary": {"use_global_defaults": True, "gateway_port": 5680, "proxy_port": 18081, "auto_start": False}},
        }, cookie)
        if install:
            request("POST", "/management/v1/gateways/primary/start", cookie=cookie)
            _, body = request("GET", "/management/v1/gateways", cookie=cookie)
            gateway = json.loads(body)["gateways"][0]
            status = gateway.get("status", gateway)
            if not status["running"] or not status["install_verified"]:
                raise RuntimeError("Gateway download/start verification failed")
            if status["authenticated"]:
                raise RuntimeError("unexpected authenticated account in fresh container")
        request("DELETE", "/auth/v1/session", cookie=cookie)
        request("GET", "/management/v1/gateways", cookie=cookie, expected=401)
        if docker("exec", name, "id", "-u") != "10001":
            raise RuntimeError("container is not using the unprivileged runtime user")
        docker("exec", name, "sh", "-c", "test ! -e /opt/ibkr-gateway && test -s /usr/local/share/ibkr-gateway-manager/licenses/go.txt")
        print(f"{scheme.upper()} image smoke passed" + (" (official Gateway download and Java startup verified)" if install else ""))
    finally:
        if started:
            subprocess.run(["docker", "rm", "--force", name], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--install-gateway", action="store_true")
    options = parser.parse_args()
    check_image(options.image, tls=False, install=options.install_gateway)
    check_image(options.image, tls=True, install=False)
