#!/usr/bin/env python3
"""Loopback M2 showing; Docket owns launch custody and the joined projection."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import pathlib
import secrets
import selectors
import stat
import subprocess
import sys
import threading
import time
import re
import urllib.parse

SCHEMA = "constellation.operator_beta.fixed_demo_status.v1"
SCENARIO = "operator-beta-systemd-http-recovery"
MAX_BYTES = 1024 * 1024
OWNER_TIMEOUT_SECONDS = 120
# Execute the retained bytes. A later replacement of the controller pathname
# cannot change this source. Its __file__ remains available for owner imports.
BOOTSTRAP = "import sys; p=sys.argv.pop(1); exec(compile(sys.stdin.buffer.read(),p,'exec'),{'__name__':'__main__','__file__':p})"


class Unavailable(Exception):
    """The adapter cannot establish current owner state."""


class Controller:
    def __init__(self, path: pathlib.Path, expected_sha256: str):
        if not path.is_absolute():
            raise ValueError("controller path must be absolute")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES:
                raise ValueError("controller must be a bounded regular file")
            with os.fdopen(os.dup(fd), "rb") as source:
                self.source = source.read(MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(self.source) > MAX_BYTES or not hmac.compare_digest(
            hashlib.sha256(self.source).hexdigest(), expected_sha256
        ):
            raise ValueError("controller bytes differ from the admitted digest")
        self.path = str(path)
        self.digest = expected_sha256

    def query(self, operation: str) -> dict:
        if operation not in ("start", "status"):
            raise ValueError("closed Docket operation")
        # Pipes are drained concurrently with a hard per-stream byte bound.
        # No operational stderr/argv is sent to the visitor.
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", "-c", BOOTSTRAP, self.path, operation],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise Unavailable("Docket execution interface is unavailable") from error
        streams = [bytearray(), bytearray()]
        deadline = time.monotonic() + OWNER_TIMEOUT_SECONDS
        selector = selectors.DefaultSelector()
        offset = 0
        for pipe, kind in ((process.stdin, "input"), (process.stdout, 0), (process.stderr, 1)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_WRITE if kind == "input" else selectors.EVENT_READ, kind)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("Docket owner reply", OWNER_TIMEOUT_SECONDS)
                for key, _ in selector.select(remaining):
                    pipe, kind = key.fileobj, key.data
                    if kind == "input":
                        offset += os.write(pipe.fileno(), self.source[offset:offset + 8192])
                        if offset == len(self.source):
                            selector.unregister(pipe)
                            pipe.close()
                    else:
                        chunk = os.read(pipe.fileno(), 8192)
                        streams[kind].extend(chunk)
                        if len(streams[kind]) > MAX_BYTES:
                            raise Unavailable("Docket reply exceeds the bounded projection size")
                        if not chunk:
                            selector.unregister(pipe)
                            pipe.close()
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Unavailable("Docket reply unavailable; launch outcome is uncertain. Inspect status; do not retry a producer.") from error
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()
        if process.returncode != 0:
            raise Unavailable("Docket did not return a validated projection. This does not establish whether execution started or finished.")
        raw = bytes(streams[0])
        if len(raw) > MAX_BYTES:
            raise Unavailable("Docket reply exceeds the bounded projection size")
        try:
            value = json.loads(raw, object_pairs_hook=unique_object,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
            validate_projection(value)
        except (ValueError, TypeError) as error:
            raise Unavailable("Docket projection is unavailable or incompatible") from error
        return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def validate_projection(value: dict) -> None:
    if not isinstance(value, dict) or value.get("schema") != SCHEMA or value.get("scenario") != SCENARIO:
        raise ValueError("wrong owner projection")
    for field in ("subject", "controller_custody", "runner_durable", "liveness", "execution", "live_sources", "limitations"):
        if not isinstance(value.get(field), dict):
            raise ValueError("missing owner region: " + field)
    if not isinstance(value.get("disagreements"), list):
        raise ValueError("missing disagreement region")
    if not all(isinstance(item, str) for item in value["disagreements"]):
        raise ValueError("invalid disagreement")
    for field in ("controller_custody", "runner_durable", "liveness"):
        if not isinstance(value[field].get("state"), str):
            raise ValueError("missing owner state")
    for field in ("terminal", "recovery"):
        if value["runner_durable"].get(field) is not None and not isinstance(value["runner_durable"][field], dict):
            raise ValueError("invalid runner record")
    def string(item, key):
        result = item.get(key)
        if not isinstance(result, str) or not result:
            raise ValueError("missing string: " + key)
        return result
    def digest(item, key, length=64):
        if not re.fullmatch("[0-9a-f]{" + str(length) + "}", string(item, key)):
            raise ValueError("invalid digest: " + key)
    def choice(item, key, options):
        if string(item, key) not in options:
            raise ValueError("invalid owner enum: " + key)
    def integer(item, key, minimum=0):
        if type(item.get(key)) is not int or item[key] < minimum:
            raise ValueError("invalid integer: " + key)
    def live(item):
        if not isinstance(item, dict):
            raise ValueError("missing live source")
        choice(item, "source", {"user-systemd", "OS process table", "OS process table plus retained Docket launch acceptance"})
        choice(item, "state", {"PROCESS_ACTIVE", "PROCESS_EXITED", "NOT_OBSERVABLE"})
        if item["state"] == "NOT_OBSERVABLE":
            string(item, "reason")
        else:
            integer(item, "main_pid", 1 if item["state"] == "PROCESS_ACTIVE" else 0)
        if item["state"] == "PROCESS_ACTIVE":
            integer(item, "start_ticks", 1)
            digest(item, "invocation_id", 32)
            digest(item, "execution_sha256")
            if type(item.get("execution_matches")) is not bool:
                raise ValueError("missing execution comparison")
        if "manager_testimony" in item:
            live(item["manager_testimony"])

    string(value["subject"], "run_id")
    digest(value["subject"], "spec_sha256")
    custody = value["controller_custody"]
    choice(custody, "source", {"Docket fixed controller"})
    choice(custody, "state", {"NO_INTENT_RECORDED", "ACCEPTANCE_VALIDATED", "INDETERMINATE"})
    runner = value["runner_durable"]
    choice(runner, "source", {"composition owner records"})
    if not {"terminal", "recovery"} <= runner.keys():
        raise ValueError("missing retained runner regions")
    terminal, recovery = runner["terminal"], runner["recovery"]
    if recovery is not None:
        choice(recovery, "state", {"REOPENED", "INDETERMINATE"})
        if recovery["state"] == "INDETERMINATE":
            string(recovery, "reason")
        else:
            for key in ("phase", "last_completed_phase", "next_lawful_action", "effect_outcome"):
                string(recovery, key)
            producer = recovery.get("producer")
            if not isinstance(producer, dict):
                raise ValueError("missing retained producer")
            string(producer, "systemd_unit")
            digest(producer, "invocation_id", 32)
            integer(producer, "main_pid", 1)
            integer(producer, "start_ticks", 1)
    if terminal is not None:
        choice(terminal, "state", {"TERMINAL", "REFUSED", "INDETERMINATE"})
        choice(terminal, "owner", {"Docket"})
        if terminal["state"] == "INDETERMINATE":
            string(terminal, "reason")
        else:
            string(terminal, "disposition")
            string(terminal, "evidence")
            choice(terminal, "replay", {"check-run"} if terminal["state"] == "TERMINAL" else {"check-refusal"})
            if terminal["state"] == "REFUSED" and terminal["disposition"] != "REFUSED":
                raise ValueError("invalid refusal disposition")
            if terminal["state"] == "TERMINAL" and terminal["disposition"] != "ONE_SPEND_ONE_ATTEMPT_BOUNDED_EFFECT_CUSTODY_WITH_DECLARED_LIMITATIONS":
                raise ValueError("incompatible fixed terminal disposition")
    # The owner supplies its phase; the adapter checks correspondence only and
    # carries no list of workflow phases or lawful transition implementation.
    expected = terminal["state"] if terminal else recovery.get("phase", recovery["state"]) if recovery else "NOT_OBSERVABLE"
    if runner["state"] != expected:
        raise ValueError("runner state has no matching retained owner region")
    live(value["liveness"])
    if set(value["live_sources"]) != {"manager", "os"}:
        raise ValueError("missing live source axes")
    for item in value["live_sources"].values():
        live(item)
    execution = value["execution"]
    choice(execution, "identity", {"BOUNDED_COMPOSITION_RUNNER"})
    choice(execution, "model_provider", {"NOT_APPLICABLE"})
    digest(execution, "producer_subject", 40)
    for key in ("producer_sha256", "checker_sha256", "controller_sha256", "code_capsule_sha256"):
        digest(execution, key)
    if not isinstance(value.get("evidence"), list) or not value["evidence"]:
        raise ValueError("missing evidence ledger")
    for entry in value["evidence"]:
        if not isinstance(entry, dict):
            raise ValueError("invalid evidence entry")
        for key in ("source", "label", "evidence"):
            string(entry, key)
        choice(entry, "source", {"AG-ng", "NQ-ng", "Docket", "NQ-ng / OS"})
        choice(entry, "state", {"MISSING", "RECORDED_UNVERIFIED", "OWNER_VALIDATED", "NOT_OBSERVABLE"})
        if "detail" in entry:
            string(entry, "detail")
    expected_limits = {"aggregate_postcondition": "NOT_RECORDED", "literal_distributed_exactly_once": "NOT_CLAIMED",
                       "signed_upstream_checksum": "NOT_QUALIFIED", "deployment": "NOT_RUN", "production": "NOT_RUN"}
    if value["limitations"] != expected_limits:
        raise ValueError("incompatible fixed scenario limitations")


PAGE = r'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Investigate · Constellation</title><style>
body{font:17px/1.5 system-ui,sans-serif;max-width:1000px;margin:3rem auto;padding:0 1.5rem;color:#172027;background:#f6f5f1}
h1{font-size:2.6rem;margin-bottom:.3rem}h2{font-size:1.15rem}button{font:700 1.1rem system-ui;padding:.8rem 2.5rem;background:#164f48;color:white;border:0;border-radius:4px;cursor:pointer}button:disabled{opacity:.5;cursor:default}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}section{background:white;border:1px solid #d6d9d7;padding:1rem;margin:1rem 0;border-radius:5px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.5 ui-monospace,monospace}.muted{color:#52616a}.notice{border-left:5px solid #ae6922;padding:1rem;background:#fff2df}#terminal{font-size:1.2rem}a{color:#164f48}.evidence-row{padding:.7rem 0;border-bottom:1px solid #e5e7e5}.evidence-row strong{display:block}.evidence-row small{display:block;color:#52616a}
</style><h1>Investigate</h1>
<p>Can a bounded, authorized service action run once through the governed execution path, with independently checked observations and retained evidence?</p>
<p class="muted">This fixed local demonstration uses two virtual machines, AG-ng, Docket, and NQ-ng. The deterministic runner performs the work; Docket's evidence checks determine what can be claimed.</p>
<form method="post" action="/run"><input type="hidden" name="token" value="TOKEN"><button id="run" disabled>RUN</button></form>
<p id="launch-note">Reading Docket launch custody…</p><p id="notice" class="notice" hidden></p>
<div class="grid"><section><h2>Investigation state</h2><div id="durable">NOT_OBSERVABLE</div><p class="muted">Retained composition records</p></section>
<section><h2>Execution right now</h2><div id="live">NOT_OBSERVABLE</div><p class="muted">Current manager / operating-system testimony</p><details><summary>Process evidence</summary><pre id="live-detail"></pre></details></section></div>
<section><h2>Current warranted result</h2><div id="terminal">No validated terminal record observed.</div><pre id="reason"></pre></section>
<div class="grid"><section><h2>Launch custody</h2><pre id="custody"></pre></section><section><h2>Who is doing the work?</h2><pre id="worker"></pre><details><summary>Exact execution identities</summary><pre id="execution-detail"></pre></details><p class="muted">Worker handoff is not supported for this producer occurrence.</p></section></div>
<section><h2>Evidence and next required step</h2><div id="evidence"></div><pre id="next"></pre></section>
<section><h2>Receipt and replay</h2><pre id="receipt">No validated terminal receipt observed.</pre><a href="/api/v1/status">Inspect current source-labeled JSON</a></section>
<details><summary>Source agreement and limitations</summary><pre id="sources"></pre><pre id="limits"></pre></details>
<p class="muted">Refreshing this page queries Docket again. It never starts another execution. Process exit and a completed HTTP request do not establish a successful investigation.</p>
<script nonce="TOKEN">
const el=id=>document.getElementById(id), text=(id,v)=>el(id).textContent=typeof v==='string'?v:JSON.stringify(v,null,2);
function ledger(entries,recovery){const root=el('evidence');root.replaceChildren();
 if(!Array.isArray(entries)){text('evidence','Separate evidence ledger NOT_OBSERVABLE.');return;}
 const labels={MISSING:'Required evidence not yet present',RECORDED_UNVERIFIED:'Recorded; owner validation pending',OWNER_VALIDATED:'Validated by the evidence owner',NOT_OBSERVABLE:'Evidence could not be observed'};
 for(const item of entries){const row=document.createElement('div');row.className='evidence-row';
 const title=document.createElement('strong');title.textContent=item.label||'Owner evidence';row.append(title);
 const status=document.createElement('span');status.textContent=labels[item.state]||item.state||'NOT_OBSERVABLE';row.append(status);
 const source=document.createElement('small');source.textContent='Source: '+(item.source||'NOT_OBSERVABLE')+' · '+(item.state||'NOT_OBSERVABLE');row.append(source);
 const detail=document.createElement('details'),summary=document.createElement('summary'),ref=document.createElement('pre');summary.textContent='Inspect evidence reference';ref.textContent=JSON.stringify({evidence:item.evidence,detail:item.detail},null,2);detail.append(summary,ref);row.append(detail);root.append(row);}}
let pending=false;
document.querySelector('form').addEventListener('submit',()=>{el('run').disabled=true;text('launch-note','Request sent to Docket. Reopening its retained state…');});
async function refresh(){if(pending)return;pending=true;try{
 const response=await fetch('/api/v1/status',{cache:'no-store'}), value=await response.json();
 if(!response.ok)throw Error(value.message||'Docket unavailable');
 const runner=value.runner_durable, terminal=runner.terminal;
 text('durable',runner.state);text('live',value.liveness.state);text('live-detail',value.liveness);text('custody',value.controller_custody);text('worker',value.execution.identity+'\nModel/provider: '+value.execution.model_provider);text('execution-detail',value.execution);
 text('terminal',terminal?terminal.disposition||terminal.state:'No validated terminal record observed.');
 text('reason',terminal&&terminal.reason||'');
 ledger(value.evidence,runner.recovery);
 text('next',runner.recovery&&runner.recovery.next_lawful_action||'Next required transition: NOT_OBSERVABLE');
 text('receipt',terminal&&terminal.evidence?{owner:terminal.owner,evidence:terminal.evidence,replay:terminal.replay}:'No validated terminal receipt observed.');
 text('sources',{disagreements:value.disagreements,live_sources:value.live_sources});text('limits',value.limitations);
 const ready=value.controller_custody.state==='NO_INTENT_RECORDED'&&value.disagreements.length===0;
 el('run').disabled=!ready;text('launch-note',ready?'Ready to request the one admitted execution.':'Docket has retained launch custody or unresolved evidence. RUN is unavailable; inspect the state below.');
 el('notice').hidden=value.disagreements.length===0;text('notice',value.disagreements.join('\n'));
 }catch(error){el('run').disabled=true;el('notice').hidden=false;text('notice','Current state NOT_OBSERVABLE: '+error.message);
 for(const id of ['durable','live','live-detail','terminal','reason','custody','worker','execution-detail','evidence','next','receipt','sources','limits'])text(id,'NOT_OBSERVABLE');
 text('launch-note','Current owner query unavailable. Previous snapshot cleared; refresh will query the owner again.');}
 finally{pending=false;setTimeout(refresh,3000);}}
refresh();
</script></html>'''


class DemoServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, controller):
        if not ipaddress.ip_address(address[0]).is_loopback:
            raise ValueError("demo must bind a numeric loopback address")
        super().__init__(address, Handler)
        self.controller = controller
        self.token = secrets.token_urlsafe(32)
        self.owner_query = threading.Lock()
        self.request_slots = threading.BoundedSemaphore(8)
        self.origin = f"http://{self.server_address[0]}:{self.server_address[1]}"

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()

    def query(self, operation):
        if not self.owner_query.acquire(timeout=2):
            raise Unavailable("Docket query already in progress; current state is not yet observable")
        try:
            return self.controller.query(operation)
        finally:
            self.owner_query.release()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ConstellationDemo/1"
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        # Requests contain no authoritative progress facts; do not collect URLs.
        pass

    def parse_request(self):
        if not super().parse_request():
            return False
        if len(self.raw_requestline) + sum(len(key) + len(value) + 4 for key, value in self.headers.items()) > 16384:
            self.send_error(431, "Request headers exceed the fixed demo bound")
            return False
        return True

    def reply(self, code, body, kind="application/json", location=None):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", f"default-src 'none'; script-src 'nonce-{self.server.token}'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def valid_host(self):
        return self.headers.get_all("Host") == [self.server.origin.removeprefix("http://")]

    def do_GET(self):
        if not self.valid_host():
            return self.reply(400, '{"message":"Unexpected host"}')
        if self.path in ("/", "/?launch=unconfirmed"):
            page = PAGE.replace("TOKEN", self.server.token)
            if self.path != "/":
                page = page.replace("<form method", '<p class="notice">The last RUN reply was unavailable. Its outcome is uncertain. Current Docket evidence is shown below; the screen did not retry.</p><form method')
            return self.reply(200, page, "text/html; charset=utf-8")
        if self.path != "/api/v1/status":
            return self.reply(404, '{"message":"Unknown view"}')
        try:
            value = self.server.query("status")
            self.reply(200, json.dumps(value))
        except Unavailable as error:
            self.reply(503, json.dumps({"source":"AG demo adapter", "state":"NOT_OBSERVABLE", "message":str(error)}))

    do_HEAD = do_GET

    def do_POST(self):
        if self.path != "/run":
            return self.reply(404, '{"message":"Unknown action"}')
        if not self.valid_host() or self.headers.get_all("Origin") != [self.server.origin]:
            return self.reply(403, '{"message":"RUN requires the local showing origin"}')
        if self.headers.get("Transfer-Encoding") or self.headers.get_all("Content-Length") is None or len(self.headers.get_all("Content-Length")) != 1:
            return self.reply(400, '{"message":"Bounded form required"}')
        try:
            length = int(self.headers["Content-Length"])
            if not 0 < length <= 256:
                raise ValueError("length")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("incomplete")
            fields = urllib.parse.parse_qs(body.decode("ascii"), strict_parsing=True)
            if fields != {"token": [self.server.token]}:
                raise ValueError("form")
        except (ValueError, UnicodeError):
            return self.reply(400, '{"message":"Invalid fixed RUN form"}')
        # No retry or new run identity is invented here. Docket serializes and
        # applies its one-intent law even if requests or connections repeat.
        try:
            self.server.query("start")
        except Unavailable:
            return self.reply(303, b"", location="/?launch=unconfirmed")
        self.reply(303, b"", location="/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", required=True, type=pathlib.Path)
    parser.add_argument("--controller-sha256", required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = DemoServer(("127.0.0.1", args.port), Controller(args.controller, args.controller_sha256))
    print(f"Fixed Constellation showing: {server.origin}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
