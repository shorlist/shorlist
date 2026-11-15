"""Adapter for the QCI PQC scanner (https://github.com/Quantum-Core-Institute-Inc/qci-pqc-scanner),
`qci-pqc scan TREE --reproducible --adapter internal --out DIR`, reading DIR/cbom.json.
QCI's scanner is MIT-licensed; this adapter only runs it and parses the CBOM it writes.

The invocation is the one the CBOM Benchmark's tools/release_run.sh uses for this scanner
(QCI_CMD, benchmark 2.6.6), minus `--json`, which only changes what goes to stdout.

Mapping: the shared CycloneDX rules in _cyclonedx.py, plus aliases for QCI spellings that the
families.yaml vocabulary does not hold, each tied to where QCI 2.3.4.5 defines the name:
- "Ed25519", "Ed448", "SSH-Ed25519-HostKey" -> EdDSA (the same spelling rule as qrp_mcp.py);
- "ECC-P-256", "ECC-P-384" -> EC (scanner.py L131, params.py L400: an EC key by curve);
- "DESede", "DESEDE" -> 3DES (classfile.py L239 _CIPHER: "DESEDE": "3DES");
- "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024" -> ML-KEM (TLS hybrid group names;
  ShorList's hybrid rows expect family ML-KEM, e.g. SL-6504).
QCI's risk-signal categories ("DH/ECDH", "Hybrid-Named", "SSH-Weak-Kex", "TLS-Classical-Cipher",
TLS cipher-suite names, ...) are not mapped: they do not name one family, which is the same
strict treatment the QCI benchmark's own adapter gives them (tools/adapters/qci_pqc.py, 1.3).
role: from primitive (_cyclonedx); size: None (QCI writes sizes in a "qci:key_size" property
that also carries modes such as "CBC", so it is not read). is_use: True (no not-a-use marker in
the CBOM). cwe: None. The scanner may exit 1 (incomplete-scan gate) with a valid cbom.json.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import _cyclonedx
from .base import Adapter, Record

ALIASES = {"Ed25519": "EdDSA", "Ed448": "EdDSA", "SSH-Ed25519-HostKey": "EdDSA",
           "ECC-P-256": "EC", "ECC-P-384": "EC", "DESede": "3DES", "DESEDE": "3DES",
           "X25519MLKEM768": "ML-KEM", "SecP256r1MLKEM768": "ML-KEM", "SecP384r1MLKEM1024": "ML-KEM"}


class QciPqcAdapter(Adapter):
    name = "qci-pqc"
    default_command = ["qci-pqc"]

    def version(self) -> str:
        p = subprocess.run(self.command + ["--version"], capture_output=True, text=True, timeout=300)
        return (p.stdout or p.stderr).strip()

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = workdir / "qci-out"
        p = subprocess.run(self.command + ["scan", str(tree), "--reproducible", "--adapter", "internal",
                                           "--out", str(out)], capture_output=True, text=True, timeout=600)
        f = out / "cbom.json"
        if not f.exists():
            raise RuntimeError(f"qci-pqc wrote no CBOM (exit {p.returncode}): {p.stderr.strip()[-500:]}")
        return self.parse(json.loads(f.read_text()))

    @staticmethod
    def parse(bom: dict) -> list[Record]:
        return _cyclonedx.records(bom, aliases=ALIASES)
