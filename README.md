# j4s-checker

**CVE-2026-114938 ("Java4Shell")** — bounded, live demonstration of the hardware-gated
AVX-512 Base64-decoder heap overflow in OpenJDK.

A single-file Java web app that runs [Calif's bounded proof-of-concept](https://calif.io/java4shell):
a malformed 65-byte Base64 input (`64 × 'A' + '='`) decoded into a 4096-byte array, so the
62-byte out-of-bounds write lands **inside a real array** — it proves the corruption without
the weaponized RCE chains the researchers are holding back.

UI is styled after the [VMware Clarity (CDS) design system](https://github.com/vmware-clarity/core)
(palette derived from the Clarity core HSL tokens).

## The vulnerability

Two independent conditions must both hold for the vulnerable C2-compiled intrinsic to run:

1. **Runtime:** an unpatched OpenJDK — fixed in `17.0.21.1` / `21.0.13.1` / `25.0.5.1` / `27.0.1.1`.
2. **Hardware:** x86-64 exposing **all four** flags: `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`.

When both hold, decoding the trigger writes 62 bytes past a 50-byte buffer *before* the
`IllegalArgumentException` is thrown — enough for unauthenticated RCE and heap disclosure
("JavaBleed") in a full exploit.

## Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Clarity-styled UI |
| `GET /probe` | Runs the bounded trigger → JSON result |
| `GET /probe?run=0` | Machine/JDK/flag info, no trigger run |
| `GET /decode?b64=…` | Decodes user-supplied Base64 (the attacker-data path) |
| `GET /health` | `{"status":"UP"}` |

`/probe` result shape (vulnerable host):

```json
{
  "runtime": "21.0.13+9-LTS",
  "rejected": true,
  "bytesChanged": 62,
  "firstChangedOffset": 50,
  "lastChangedOffset": 111,
  "result": "REPRODUCED"
}
```

Interpretation:

- **REPRODUCED** — this JVM + CPU exhibits the corruption (runtime vulnerable *and* all four flags present).
- **NOT REPRODUCED** — the vulnerable path was not taken: no AVX-512 VBMI, a fixed JDK, or
  intrinsics disabled. A negative is *not* a safety verdict — JIT/JVM-option differences can suppress it.

## Running

```sh
# JDK 17.0.6+ (or any JDK in the vulnerable range; 21 shown)
javac src/J4sChecker.java
PORT=8080 java -cp src J4sChecker
```

or the prebuilt jar (Java 21):

```sh
PORT=8080 java -jar j4s-checker.jar
```

### Cloud Foundry

```sh
cf push j4s-checker --strategy=none -m 256M -i 1
```

`.java-version` pins JDK 21. (The app binds `PORT`.)

### Mitigations (for a host that reproduces)

- Patch to a fixed build, or
- Launch with `-XX:-UseBASE64Intrinsics` (or `-XX:UseAVX=2`), or
- Mask the CPU feature (`avx512vbmi`) at the hypervisor layer.

## Lab demonstration (2026-11-18)

| Space | Cluster / cells | CPU | Expected |
|---|---|---|---|
| `cody-k8s` | TKG guest `tnz-e142e57bf8` (AMD Ryzen 9 9955HX, per-VM masking exposes VBMI) | all 4 flags | **REPRODUCED** |
| `cody` | legacy BOSH cells (Intel Xeon D-1518, no AVX-512) | none | NOT REPRODUCED |

Full investigation: [`cve-2026-114938-java4shell-2026-11-18.md`](https://github.com/kirkware/kirkware-agents/blob/main/agents/alana/reports/cve-2026-114938-java4shell-2026-11-18/cve-2026-114938-java4shell-2026-11-18.md)

## Sources

- calif.io/java4shell (bounded PoC, research writeup)
- Oracle CPU / CSPU, November 2026
- ikow/java4shell-poc, fumioryoto/java4shell-poc

Treat PoC output as evidence for *this* JVM + CPU, not a general safety verdict.
