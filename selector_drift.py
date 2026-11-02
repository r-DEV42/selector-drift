#!/usr/bin/env python3
"""
Selector-drift scanner v2: finds outgoing external calls whose 4-byte selector no longer exists
in any current dependency (contract calls claim(), the dependency was upgraded and
removed it, so the call always reverts).

An orphan is CONFIRMED when the selector existed in an earlier implementation of a dependency;
only CONFIRMED orphans are strong leads. Stdlib only.

Honesty rules: an RPC failure is never read as "no code"; every address gets a status line; a target
whose dependencies could not all be resolved is flagged INCOMPLETE and never reported as clean.
Limits: runtime-supplied targets (clones, registries, user tokens) cause false orphans; behavior
changes with the selector still present are invisible; diamonds resolve poorly.

Usage:
  python3 -I selector_drift.py --rpc URL[,URL2,...] [--file addrs.txt] [--slots 200] [--depth 1]
      [--extra-deps a,b] [--strict] [--only-confirmed] [--no-history] [--json out.json] [ADDR ...]
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ---------------- keccak256 (stdlib has no keccak) ----------------
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(v, r):
    return ((v << r) | (v >> (64 - r))) & _M if r else v


def _keccak_f(A):
    for rc in _RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol(A[x][y], _ROT[x][y])
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01"
    while len(msg) % rate:
        msg += b"\x00"
    msg[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        A = _keccak_f(A)
    return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def selector(sig: str) -> str:
    return keccak256(sig.encode()).hex()[:8]


assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
assert selector("transfer(address,uint256)") == "a9059cbb"

STANDARD_SIGS = [
    "transfer(address,uint256)", "transferFrom(address,address,uint256)", "approve(address,uint256)",
    "balanceOf(address)", "allowance(address,address)", "totalSupply()", "decimals()", "symbol()", "name()",
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", "nonces(address)", "DOMAIN_SEPARATOR()",
    "ownerOf(uint256)", "safeTransferFrom(address,address,uint256)", "safeTransferFrom(address,address,uint256,bytes)",
    "getApproved(uint256)", "isApprovedForAll(address,address)", "setApprovalForAll(address,bool)",
    "supportsInterface(bytes4)", "tokenURI(uint256)",
    "balanceOfBatch(address[],uint256[])", "safeTransferFrom(address,address,uint256,uint256,bytes)",
    "asset()", "totalAssets()", "convertToShares(uint256)", "convertToAssets(uint256)", "maxDeposit(address)",
    "previewDeposit(uint256)", "deposit(uint256,address)", "maxMint(address)", "previewMint(uint256)",
    "mint(uint256,address)", "maxWithdraw(address)", "previewWithdraw(uint256)", "withdraw(uint256,address,address)",
    "maxRedeem(address)", "previewRedeem(uint256)", "redeem(uint256,address,address)",
    "owner()", "transferOwnership(address)", "renounceOwnership()", "pendingOwner()", "acceptOwnership()",
    "hasRole(bytes32,address)", "getRoleAdmin(bytes32)", "grantRole(bytes32,address)", "revokeRole(bytes32,address)",
    "paused()", "pause()", "unpause()", "implementation()", "proxiableUUID()", "upgradeTo(address)",
    "upgradeToAndCall(address,bytes)", "initialize()", "getRoundData(uint80)", "latestRoundData()",
    "latestAnswer()", "description()", "version()", "multicall(bytes[])", "onERC721Received(address,address,uint256,bytes)",
    "onERC1155Received(address,address,uint256,uint256,bytes)", "mint(address,uint256)", "burn(uint256)",
    "burn(address,uint256)", "burnFrom(address,uint256)", "deposit()", "withdraw(uint256)",
]
STANDARD = {selector(s) for s in STANDARD_SIGS}
DYNAMIC_HINT = re.compile(r"registry|factory|router|connector|resolver|addressprovider|locator|directory", re.I)


# ---------------- RPC ----------------
class RpcFail(Exception):
    pass


class RPC:
    """Several endpoints; network failures rotate endpoints and retry, JSON-RPC errors return None."""

    def __init__(self, urls):
        self.urls = urls
        self.cache = {}
        self.chain_id = None

    def _post(self, body, attempts=6):
        last = None
        for attempt in range(attempts):
            url = self.urls[attempt % len(self.urls)]
            try:
                req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                return json.loads(urllib.request.urlopen(req, timeout=40).read())
            except urllib.error.HTTPError as e:
                last = e
                if e.code in (400, 401, 403, 404):  # definitive refusal (e.g. archive/log range): return its JSON error
                    try:
                        body_json = json.loads(e.read())
                        if isinstance(body_json, dict) and "error" in body_json:
                            return body_json
                    except Exception:
                        pass
                time.sleep(min(1 + attempt, 4))
            except Exception as e:  # network, bad JSON
                last = e
                time.sleep(min(1 + attempt, 4))
        raise RpcFail(str(last))

    def call(self, method, params):
        key = (method, json.dumps(params))
        if key in self.cache:
            return self.cache[key]
        for attempt in range(4):
            r = self._post(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())
            if isinstance(r, dict) and "error" in r:
                msg = json.dumps(r["error"]).lower()
                if any(w in msg for w in ("rate", "limit exceeded", "too many", "timeout", "capacity")) and attempt < 3:
                    time.sleep(2 + attempt)
                    continue
                self.cache[key] = None
                return None
            res = r.get("result") if isinstance(r, dict) else None
            self.cache[key] = res
            return res
        return None

    def batch(self, calls, chunk=40):
        out = []
        for i in range(0, len(calls), chunk):
            part = calls[i:i + chunk]
            body = json.dumps([{"jsonrpc": "2.0", "id": j, "method": m, "params": p} for j, (m, p) in enumerate(part)]).encode()
            res = [None] * len(part)
            try:
                r = self._post(body, attempts=3)
                if not isinstance(r, list):
                    raise RpcFail("no batch support")
                for it in r:
                    if isinstance(it, dict) and "result" in it:
                        res[it["id"]] = it["result"]
            except RpcFail:
                res = [self.call(m, p) for m, p in part]
            out += res
        return out

    def code(self, a):
        r = self.call("eth_getCode", [a, "latest"])
        if r is None:
            raise RpcFail("eth_getCode returned no result for " + a)
        return bytes.fromhex(r[2:]) if r != "0x" else b""

    def storage(self, a, slot):
        r = self.call("eth_getStorageAt", [a, hex(slot) if isinstance(slot, int) else slot, "latest"])
        return r or "0x" + "00" * 32

    def eth_call(self, a, data):
        return self.call("eth_call", [{"to": a, "data": data}, "latest"])

    def get_chain_id(self):
        if self.chain_id is None:
            try:
                self.chain_id = int(self.call("eth_chainId", []), 16)
            except Exception:
                self.chain_id = 0
        return self.chain_id


def addr_from_word(w):
    if not w or not isinstance(w, str):
        return None
    h = w[2:].rjust(64, "0")
    if len(h) != 64 or h[:24] != "0" * 24:
        return None
    a = "0x" + h[24:]
    return a if int(a, 16) > 0xFFFF else None


IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
PROXIABLE_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
SAFE_MASTERCOPY_SEL = bytes.fromhex("a619486e")


def resolve_impl(rpc, a, hops=0):
    """Return (impl_address_or_self, kind). Raises RpcFail on network failure."""
    if hops > 3:
        return a, "deep"
    code = rpc.code(a)
    if len(code) == 45 and code.startswith(bytes.fromhex("363d3d373d3d3d363d73")):
        return resolve_impl(rpc, "0x" + code[10:30].hex(), hops + 1)[0], "eip1167"
    if len(code) == 0:
        return a, "eoa"
    t = addr_from_word(rpc.storage(a, IMPL_SLOT))
    if t:
        return resolve_impl(rpc, t, hops + 1)[0], "eip1967"
    b = addr_from_word(rpc.storage(a, BEACON_SLOT))
    if b:
        r = rpc.eth_call(b, "0x5c60da1b")
        t = addr_from_word(r) if r else None
        if t:
            return resolve_impl(rpc, t, hops + 1)[0], "beacon"
    t = addr_from_word(rpc.storage(a, PROXIABLE_SLOT))
    if t:
        return resolve_impl(rpc, t, hops + 1)[0], "eip1822"
    if len(code) < 300 and SAFE_MASTERCOPY_SEL in code:
        t = addr_from_word(rpc.storage(a, 0))
        if t:
            return resolve_impl(rpc, t, hops + 1)[0], "safe"
    if len(code) < 3000:
        r = rpc.eth_call(a, "0x5c60da1b")
        t = addr_from_word(r) if r and len(r) == 66 else None
        if t and rpc.code(t):
            return resolve_impl(rpc, t, hops + 1)[0], "implementation()"
    return a, "direct"


# ---------------- bytecode analysis ----------------
def strip_metadata(code):
    if len(code) > 2:
        n = int.from_bytes(code[-2:], "big")
        if 0 < n < 120 and len(code) > n + 2 and 0xA0 <= code[-n - 2] <= 0xAF:
            return code[:-n - 2]
    return code


def walk(code):
    ops, i = [], 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            ops.append((i, op, code[i + 1:i + 1 + n]))
            i += 1 + n
        else:
            ops.append((i, op, b""))
            i += 1
    return ops


CALLS = {0xF1, 0xF2, 0xF4, 0xFA}
ENDS = {0xFD, 0xF3, 0x00, 0xFE}


def classify(ops, start):
    for _, op, _ in ops[start:start + 160]:
        if op in CALLS:
            return "call"
        if op in ENDS:
            return "end"
    return "unclear"


def analyze(code):
    ops = walk(strip_metadata(code))
    dispatch, outgoing, addrs = set(), {}, set()
    for k, (pc, op, data) in enumerate(ops):
        if op == 0x63:  # PUSH4
            sel = data.hex()
            nxt = [o[1] for o in ops[k + 1:k + 3]]
            if 0x14 in nxt:
                dispatch.add(sel)
            if len(ops) > k + 3 and ops[k + 1][1] == 0x60 and ops[k + 1][2] == b"\xe0" and ops[k + 2][1] == 0x1B:
                outgoing.setdefault(sel, set()).add(classify(ops, k + 3))
        elif op == 0x7F and len(data) == 32 and data[4:] == b"\x00" * 28 and data[:4] != b"\x00" * 4:
            outgoing.setdefault(data[:4].hex(), set()).add(classify(ops, k + 1))
        if op == 0x73 and len(data) == 20:
            addrs.add("0x" + data.hex())
        elif op == 0x7F and len(data) == 32 and data[:12] == b"\x00" * 12 and data[12:] != b"\x00" * 20:
            addrs.add("0x" + data[12:].hex())
    return dispatch, outgoing, addrs


# ---------------- external data: 4byte names, Blockscout ABI/logs ----------------
def http_json(url, timeout=30, tries=5):
    last = None
    for i in range(tries):
        try:
            return json.loads(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=timeout).read())
        except urllib.error.HTTPError as e:
            last = e
            if e.code not in (429, 500, 502, 503, 504):
                raise
        except Exception as e:
            last = e
        time.sleep(2 * (i + 1))
    raise last


def names(sels):
    out = {}
    if not sels:
        return out
    try:
        r = http_json("https://api.openchain.xyz/signature-database/v1/lookup?function=" + ",".join("0x" + s for s in sels), 20)
        for k, v in (r.get("result", {}).get("function") or {}).items():
            if v:
                out[k[2:]] = v[0]["name"]
    except Exception:
        pass
    return out


BLOCKSCOUT = {1: "eth", 10: "optimism", 100: "gnosis", 137: "polygon", 8453: "base", 42161: "arbitrum"}


def blockscout_host(rpc):
    h = BLOCKSCOUT.get(rpc.get_chain_id())
    return f"https://{h}.blockscout.com" if h else None


def abi_address_getters(rpc, impl):
    """Zero-arg view functions returning a single address, from the verified ABI (empty if unverified)."""
    host = blockscout_host(rpc)
    if not host:
        return []
    ck = f"{rpc.get_chain_id()}:{impl.lower()}"
    cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".drift_abi_cache.json")
    try:
        cache = json.load(open(cache_path))
    except Exception:
        cache = {}
    if ck in cache:
        return cache[ck]
    try:
        r = http_json(f"{host}/api/v2/smart-contracts/{impl}", tries=2)
    except urllib.error.HTTPError as e:
        if e.code == 404:  # unverified: remember it so we stop asking
            cache[ck] = []
            try:
                json.dump(cache, open(cache_path, "w"))
            except Exception:
                pass
        return []
    except Exception:
        return []
    def all_addr(o):
        if o.get("type") == "address":
            return True
        return o.get("type") == "tuple" and bool(o.get("components")) and all(all_addr(c) for c in o["components"])

    out = []
    for f in r.get("abi") or []:
        if (f.get("type") == "function" and f.get("stateMutability") in ("view", "pure") and not f.get("inputs")
                and f.get("outputs") and all(all_addr(o) for o in f["outputs"])):
            out.append(f["name"])
    cache[ck] = out
    try:
        json.dump(cache, open(cache_path, "w"))
    except Exception:
        pass
    return out


UPGRADED_TOPIC = "0x" + keccak256(b"Upgraded(address)").hex()


import os
_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".drift_history_cache.json")
try:
    _HIST_CACHE = json.load(open(_CACHE_FILE))
except Exception:
    _HIST_CACHE = {}


def _save_cache():
    try:
        json.dump({k: v for k, v in _HIST_CACHE.items() if v is not None}, open(_CACHE_FILE, "w"))
    except Exception:
        pass


def impl_history(rpc, proxy):
    """List of past implementations, or None when no source could provide the history."""
    if proxy.lower() in _HIST_CACHE:
        return _HIST_CACHE[proxy.lower()]
    logs = rpc.call("eth_getLogs", [{"address": proxy, "topics": [UPGRADED_TOPIC], "fromBlock": "0x0", "toBlock": "latest"}])
    if logs is None:
        host = blockscout_host(rpc)
        if host:
            try:
                r = http_json(f"{host}/api?module=logs&action=getLogs&fromBlock=0&toBlock=latest&address={proxy}&topic0={UPGRADED_TOPIC}")
                logs = r["result"] if isinstance(r.get("result"), list) else None
            except Exception:
                logs = None
            time.sleep(0.5)
    if logs is None:
        _HIST_CACHE[proxy.lower()] = None
        return None
    out = []
    for lg in logs:
        t = addr_from_word(lg["topics"][1]) if len(lg.get("topics", [])) > 1 and lg["topics"][1] else None
        if t and t.lower() not in out:
            out.append(t.lower())
    _HIST_CACHE[proxy.lower()] = out
    _save_cache()
    return out


# ---------------- scan ----------------
def scan(rpc, target, slots, extra, depth, seen, level=1, show_unclear=False, strict=False, history=True):
    if target.lower() in seen:
        return []
    seen.add(target.lower())
    row = {"target": target, "level": level, "status": "ok", "complete": True, "impl": None, "proxy_kind": None,
           "outgoing": 0, "deps": {}, "orphans": [], "weak_standard_matches": [], "removed_but_not_called": [],
           "dynamic_getters": [], "notes": []}
    try:
        impl, kind = resolve_impl(rpc, target)
        row["impl"], row["proxy_kind"] = impl, kind
        code = rpc.code(impl)
    except RpcFail as e:
        row["status"], row["complete"] = "UNKNOWN (rpc failure: " + str(e)[:60] + ")", False
        return [row]
    if not code:
        row["status"] = "NO CODE (EOA or self-destructed)"
        return [row]
    dispatch, outgoing, code_addrs = analyze(code)
    row["outgoing"] = len(outgoing)
    cand = set(a.lower() for a in code_addrs) | set(a.lower() for a in extra)

    getters = abi_address_getters(rpc, impl)
    if getters:
        res = rpc.batch([("eth_call", [{"to": target, "data": "0x" + selector(g + "()")}, "latest"]) for g in getters])
        for g, w in zip(getters, res):
            if not isinstance(w, str) or len(w) < 66:
                continue
            h = w[2:]
            for i in range(0, len(h) - 63, 64):  # every 32-byte word of a multi-address / struct return
                a = addr_from_word("0x" + h[i:i + 64])
                if a:
                    cand.add(a.lower())
                    if DYNAMIC_HINT.search(g) and g not in row["dynamic_getters"]:
                        row["dynamic_getters"].append(g)
    else:
        row["notes"].append("no verified ABI: dependencies come only from code + storage")

    n0 = min(slots, 64)
    words = rpc.batch([("eth_getStorageAt", [target, hex(s), "latest"]) for s in range(n0)])
    if slots > n0 and not any(addr_from_word(w) for w in words) and len(cand) <= len(code_addrs):
        words += rpc.batch([("eth_getStorageAt", [target, hex(s), "latest"]) for s in range(n0, slots)])
    for w in words:
        a = addr_from_word(w)
        if a:
            cand.add(a.lower())
    cand.discard(target.lower())
    cand.discard(impl.lower())

    deps = {}
    for a in sorted(cand):
        try:
            if not rpc.code(a):
                continue
            di, dk = resolve_impl(rpc, a)
            dd, _, _ = analyze(rpc.code(di))
            deps[a] = {"impl": di, "kind": dk, "sels": dd, "doubtful": len(dd) < 3, "removed": {}}
        except RpcFail as e:
            deps[a] = {"impl": None, "kind": "UNKNOWN", "sels": set(), "doubtful": True, "removed": {}}
            row["complete"] = False
            row["notes"].append(f"dep {a} unresolved: {str(e)[:80]}")
    if not deps and not code_addrs and not extra and outgoing:
        row["notes"].append("0 dependencies found: nothing to compare against")
        row["complete"] = False

    dep_sels = set()
    for d in deps.values():
        dep_sels |= d["sels"]
    known_strong = set(dispatch) | dep_sels
    known = known_strong if strict else known_strong | STANDARD
    orphans = {s: ("call" if "call" in c else "unclear") for s, c in outgoing.items() if s not in known and "end" not in c}
    if not show_unclear:
        orphans = {s: c for s, c in orphans.items() if c == "call"}
    if history and orphans:  # lazy: only pay the explorer cost when there is something to confirm
        for a, d in deps.items():
            if d["kind"] != "eip1967" or not d["impl"]:
                continue
            hist = impl_history(rpc, a)
            if hist is None:
                row["notes"].append(f"upgrade history unavailable for dep {a}: CONFIRMED tags may be missing")
                continue
            for old in hist:
                if old == d["impl"].lower():
                    continue
                try:
                    od, _, _ = analyze(rpc.code(old))
                except RpcFail:
                    continue
                for s in od - d["sels"]:
                    d["removed"].setdefault(s, old)
    removed_all = {}
    for a, d in deps.items():
        for s, old in d["removed"].items():
            removed_all.setdefault(s, (a, old))
    nm = names(list(orphans) + list(removed_all))
    for s, c in orphans.items():
        o = {"selector": "0x" + s, "name": nm.get(s), "ctx": c}
        if s in removed_all:
            o["confirmed_removed_from"], o["last_seen_in_impl"] = removed_all[s]
        row["orphans"].append(o)
    row["weak_standard_matches"] = ["0x" + s for s, c in outgoing.items() if s in STANDARD and s not in known_strong and "call" in c and "end" not in c]
    row["removed_but_not_called"] = [{"selector": "0x" + s, "name": nm.get(s), "dep": a} for s, (a, _) in removed_all.items() if s not in outgoing]
    row["deps"] = {a: {"impl": d["impl"], "kind": d["kind"], "n_sels": len(d["sels"]), "doubtful": d["doubtful"],
                       "removed_in_upgrades": len(d["removed"])} for a, d in deps.items()}
    res = [row]
    if level < depth:
        for a in deps:
            res += scan(rpc, a, slots, [], depth, seen, level + 1, show_unclear, strict, history)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("addrs", nargs="*")
    ap.add_argument("--rpc", required=True, help="one or more URLs, comma-separated (rotated on failure)")
    ap.add_argument("--file", help="text file with one address per line (# comments allowed)")
    ap.add_argument("--slots", type=int, default=200)
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--extra-deps", default="")
    ap.add_argument("--json")
    ap.add_argument("--show-unclear", action="store_true")
    ap.add_argument("--strict", action="store_true", help="do not treat the generic standard selector list as known")
    ap.add_argument("--no-history", action="store_true", help="skip Upgraded() history of dependencies")
    ap.add_argument("--only-confirmed", action="store_true", help="print only orphans confirmed removed by upgrade history")
    a = ap.parse_args()
    targets = list(a.addrs)
    if a.file:
        for ln in open(a.file):
            m = re.search(r"0x[0-9a-fA-F]{40}", ln.split("#")[0])
            if m:
                targets.append(m.group(0))
    if not targets:
        ap.error("no addresses given")
    rpc = RPC([u for u in a.rpc.split(",") if u])
    extra = [x for x in a.extra_deps.split(",") if x]
    allres, seen = [], set()
    for t in targets:
        allres += scan(rpc, t, a.slots, extra, a.depth, seen, 1, a.show_unclear, a.strict, not a.no_history)
    n_unknown = n_incomplete = n_orph = n_conf = 0
    for r in allres:
        if r["status"] != "ok":
            n_unknown += 1
            print(f"\n== {r['target']}  STATUS: {r['status']}")
            continue
        conf = [o for o in r["orphans"] if "confirmed_removed_from" in o]
        n_orph += len(r["orphans"])
        n_conf += len(conf)
        if not r["complete"]:
            n_incomplete += 1
        flag = "" if r["complete"] else "  INCOMPLETE (do not read as clean)"
        print(f"\n== {r['target']} (impl {r['impl']}, {r['proxy_kind']}, level {r['level']}) outgoing: {r['outgoing']}, deps: {len(r['deps'])}{flag}")
        if not a.only_confirmed:
            for d, v in r["deps"].items():
                print(f"   dep {d} -> {v['impl']} [{v['kind']}] selectors={v['n_sels']}{' DOUBTFUL' if v['doubtful'] else ''}"
                      f"{' removed-in-upgrades=' + str(v['removed_in_upgrades']) if v['removed_in_upgrades'] else ''}")
        for n in r["notes"]:
            print("   note:", n)
        shown = conf if a.only_confirmed else r["orphans"]
        for o in shown:
            nm_ = o["name"] or "?"
            tag = " [likely custom error]" if nm_[:1].isupper() and not nm_.split("(")[0].isupper() else ""
            c = (f" [CONFIRMED removed from dep {o['confirmed_removed_from']} (last seen in impl {o['last_seen_in_impl']})]"
                 if "confirmed_removed_from" in o else "")
            dyn = f" [target has runtime-resolved deps: {', '.join(r['dynamic_getters'])}]" if r["dynamic_getters"] and not c else ""
            print(f"   ORPHAN {o['selector']} {nm_} ({o['ctx']}){tag}{c}{dyn}")
        if not r["orphans"] and r["complete"]:
            print("   no orphan selectors")
        if a.strict and r["weak_standard_matches"] and not a.only_confirmed:
            print("   weak (matched only by the standard list):", ", ".join(r["weak_standard_matches"]))
        if r["removed_but_not_called"] and not a.only_confirmed:
            print(f"   info: {len(r['removed_but_not_called'])} selectors removed from deps in past upgrades and not called by this target")
    print(f"\nSUMMARY: {len(allres)} addresses, {n_unknown} UNKNOWN/NO CODE, {n_incomplete} INCOMPLETE, {n_orph} orphans, {n_conf} CONFIRMED")
    print("Note: an unconfirmed ORPHAN is usually a runtime-supplied target or a custom error. Verify by hand.")
    print("Not covered: a dependency whose function still exists but changed behavior (needs a source diff).")
    if a.json:
        json.dump(allres, open(a.json, "w"), indent=1, default=list)


if __name__ == "__main__":
    main()
