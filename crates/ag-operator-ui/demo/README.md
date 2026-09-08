# Fixed Constellation showing (M2)

This separate Python-standard-library executable hosts the fixed local M2
screen beside Phosphor-ng. The ordinary `ag-operator-ui` binary retains its
GET/HEAD-only contract. This screen owns no campaign records or execution
decisions. Docket owns `start`, `status`, the single retained launch intent,
terminal composition checks and joined evidence projection. AG-ng and NQ-ng
retain ownership of their respective authorization/effect and observation facts.
NQ-ng supplies the existing observation harness;
AG-ng supplies authorization/spend/effect behavior. Classic implementations
are not dependencies.

## Local launch

Use the independently accepted controller path and SHA-256 from the integrated
release record, after its fixed spec and inputs have been admitted:

```sh
python3 crates/ag-operator-ui/demo/fixed_demo.py \
  --controller /absolute/qualified/fixed_demo_controller.py \
  --controller-sha256 EXACT_ACCEPTED_SHA256
```

Open `http://127.0.0.1:8765/`. The fixed description explains the investigation.
RUN sends the one closed operation to Docket. It accepts no run, path, port,
model or spec selection from the browser. Startup `--port` changes only the
loopback presentation port. The controller digest is checked once and those
exact source bytes are retained for subsequent calls; Python executes those
bytes with the original `__file__` for owner module resolution. Controller
custody of its runner/imported code remains Docket's responsibility.

Every refresh/reconnect queries Docket `status`. A three-second browser timer
refreshes that projection while the page is open; it does not launch or recover
execution. Browser state is ephemeral. Repeated RUN requests reach the same
Docket controller and its one-intent rule. The screen additionally disables RUN
when current custody reports an intent or disagreement. That display choice
does not grant execution authority. Lost launch replies redirect to a visible
uncertainty notice and are never automatically retried.

Investigation position, controller custody, current process testimony, terminal
owner disposition, evidence and limitations remain separate. Refusal is an
ordinary 200 response from the owner projection. Adapter failure is 503 /
`NOT_OBSERVABLE`; all current-value regions from the previous snapshot are
cleared to `NOT_OBSERVABLE`. A process exit
or successful HTTP exchange never becomes a stronger terminal claim. JSON is
rendered as text, with no arbitrary evidence-file serving or command execution.
The terminal receipt path and owner replay verb come directly from Docket.

## Qualification boundary

```sh
python3 -m unittest discover -s crates/ag-operator-ui/demo -p 'test_*.py' -v
```

These labeled local fixtures exercise HTTP delegation, repeated requests,
refresh/reconnect, separate phase/liveness, refused/uncertain owner states,
retained controller bytes, digest/path refusals and transport failure. They do
not qualify the real controller, two-VM execution or integrated browser run.
Final qualification must bind the exact AG-ng and Docket revisions and browser
evidence, rerun the composition witness, and preserve M1 evidence at its
original subjects.

The trusted environment is the local operator account, host Python and standard
library, and admitted Docket implementation/dependencies. Browser requests are
bounded (256-byte RUN form), require the exact loopback Host/Origin and an
ephemeral form token. Owner calls serialize locally and use a 120-second reply
bound across nonblocking source transfer, output collection and process wait.
A reply timeout ends only the adapter's controller invocation; it does
not stop or restart the durable producer. Reopening Docket status is the next
step. No production deployment, provider/model use, handoff, retry, reset,
arbitrary configuration, new daemon, database or orchestration is introduced.

The display server is itself an observer/controller process; its loss removes
the browser endpoint. A fresh server reconstructs from Docket without resuming
or replacing the producer. Use the campaign's approved durable execution
mechanism and recovery checkpoint for an unattended showing or qualification;
an interactive terminal alone is not execution custody.
