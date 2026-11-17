# CVE-2026-43745 reached from a captive portal — iPhone 17 Pro Max / iOS 26.3

Research notes: triggering the WebKit Wasm exception-handling out-of-bounds write (bug 315365,
fixed in Safari/iOS 26.5.2) **from a captive-network-assistant page on an activation-locked
device**, i.e. with no app, no cable, no user interaction beyond a page load.

This is a primitive report, not an exploit. Nothing here is RCE.

> Fait sur un seul appareil, une seule nuit, sans câble USB, avec un partage de connexion
> Windows qui tombait toutes les deux minutes et un portail captif qui refusait de se rouvrir.
> C'est de la recherche de bricoleur, pas du labo. Les limites sont dites telles quelles.

---

## TL;DR

| | |
|---|---|
| Target | iPhone 17 Pro Max (A19 Pro, MIE/MTE active), iOS 26.3, iCloud-locked, no SIM |
| Vector | captive portal served by a rogue AP → `compileStreaming()` on a crafted module |
| Divergence | same bytes: `WebAssembly.validate` = false, `compile()` = `CompileError`, **`compileStreaming()` = OK** |
| Effect | calling the exported function kills the WebContent process (5/5, page goes blank, no JS exception) |
| Shaping | putting a **payload on the tag** makes the same out-of-bounds write **non-fatal** (19/19 survive) |
| Status | primitive confirmed and shaped; no controlled read/write yet |

## What is and is not proven

Proven on device:
- the compile-time divergence above, reproducibly, on a stock locked device
- a deterministic WebContent death on invocation (no exception reaches JS)
- that a tag payload turns the fault benign — the first handle on controlling the write

Not proven:
- any observable memory corruption (global, local and linear-memory sentinels were all tried
  and none were reached, once the section-ordering constraints were worked around)
- RIP control, sandbox escape, kernel. See *Open work*.

## Mechanism

The bug is in the Wasm module **end-of-module validation**. The engine verifies that a legacy
`try` + `catch_all` + `rethrow 0` agrees with the module's exception tags. `compileStreaming()`
does not perform that final check, so a module mixing legacy EH and the newer `try_table` is
rejected by the normal path but accepted by the streaming path. Later, `rethrow 0` reads a
stack slot at a control depth the emitted frame does not have.

The trigger is 56 bytes: one type, one tag, one function, `try`/`nop`/`catch_all`/`rethrow 0`
then `block`/`try_table`/`throw`.

Two generation traps worth recording: the **tag section must precede `export` and `code`**
(and follow `type`/`func`), and the Code section size is `len(body) + 2`.

## Files

```
trigger/crash_no_payload.wasm         56 B  tag ()->()      -> process dies
trigger/survives_with_payload.wasm    59 B  tag (i32)->()    -> survives
trigger/gen_wasm.py                         regenerates both, byte-exact
harness/serve.py                            rogue AP payload server (DNS spoof + TLS + probe)
harness/eh.html                             triggers the divergence and reports each step
harness/ctl.html, harness/oob.html          transport/size sweep for the brotli side-quest
```

## Reproduce

Device side is a rogue AP with DNS hijack; the portal is served on the redirect from
`captive.apple.com/hotspot-detect.html`, TLS self-signed so the CNA opens.

The wasm files must be reachable by the server: copy `trigger/*.wasm` into
`harness/pages/` as `eh_0.wasm` (crash) or `eh_1.wasm` (survivor); `serve.py` serves
`/eh.wasm` from `pages/eh_0.wasm` by default. Generate the lab certificate first:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 \
  -subj '/CN=captive.apple.com' \
  -addext 'subjectAltName=DNS:captive.apple.com,DNS:*.apple.com,IP:192.168.137.1'
```

```powershell
# on the AP host, admin for DNS/53 and HTTP/80
python -u serve.py --ip 192.168.137.2 --dns-bind 192.168.137.1,192.168.137.2 \
       --spoof-all --portal /eh.html
```

Lab `cert.pem` / `key.pem` are included so it runs out of the box (30-day self-signed) —
regenerate them with the command above for your own runs.

Then join the AP from the locked device and load the portal. Expected sequence in the log:

```
WebAssembly.validate = false
compile() = refuse (CompileError)
compileStreaming OK
instantiate + run()
[page blank — WebContent died]
```

With `survives_with_payload.wasm` the same sequence ends with the page still alive.

## Observations (16/17 Nov 2026, one device)

| case | result |
|---|---|
| `crash_no_payload` | WebContent death, 5/5 |
| `survives_with_payload` | survivor, 19/19 |
| sentinel in a module global | never reached (−1 intact) |
| sentinel in a linear memory | not reached (section-ordering blocked) |
| fixed-config sweep 90 KB → 23 MB (brotli, side-quest) | OOB read, +66..78 bytes over 5098 legitimate |

## Caveats

- Single device, single build, one operator. No instrumentation: all conclusions are from
  logs emitted by the page and from process liveness.
- The WebKit bug is restricted on Bugzilla (315365); the public description comes from
  WebKit Weekly. Apple's advisory classifies it as an out-of-bounds write and fixed it in
  Safari/iOS 26.5.2 — so 26.3 is in range.
- The brotli part (CVE-2026-111497) is a separate, weaker primitive: reliable but tiny, and
  it never exceeded ~78 bytes here; the published 8.39 MB figure did not reproduce on 26.3.

## Open work

1. Make the write observable — a memory-section variant is the natural next step; it was
   blocked by section ordering alone, so a local validator (`wasm-tools`) is the way in.
2. Sweep stack height and payload values once observable.
3. Only then: useful target, sandbox escape, kernel.

## Credit

- Bug 315365 / CVE-2026-43745 — WebKit team, analysed publicly in WebKit Weekly.
- Trigger pair `trigger_w13_*` and the OOB-read staging used for the brotli side-quest are
  from `MchinaMd57764/CVE-2026-111497-PoC` (Apple libcompression, fixed 27.2.1).
- Prior art read, not reused: `murieeltjie-lang/Apple-BP-Attempt-Sessions` (its CNA feature
  matrix wrongly concluded Wasm was blocked, which is what reopened this bug).

## License

MIT.
