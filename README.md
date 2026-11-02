# selector-drift

Finds contracts that call a function their dependency no longer has.

A protocol calls `dep.claim()`. Later the dependency is upgraded and `claim()` is removed. The call reverts every time, and nothing in the protocol's own code changed. An audit done before the dependency upgrade wouldn't have seen it.

The script checks a live contract against its dependencies' current and previous implementations. No source code needed.

## Usage

Python 3, standard library only.

```
python3 -I selector_drift.py --rpc https://ethereum-rpc.publicnode.com 0xTargetAddress
python3 -I selector_drift.py --rpc URL1,URL2 --file addresses.txt --only-confirmed --json out.json
```

`python3 selector_drift.py --help` lists the rest of the flags.

## Output

An outgoing call that no dependency has is an orphan. It is marked CONFIRMED only when the function existed in an earlier implementation of a dependency. Only CONFIRMED orphans are strong leads.

## Limits

- A function that still exists but changed behavior is invisible. That needs a source diff.
- Targets supplied at runtime (clones, registries, user tokens) show up as orphans that aren't real. Check them by hand.
- If a dependency can't be resolved, the address is marked `INCOMPLETE`, never clean.
- Diamonds resolve poorly.

An unconfirmed orphan is a lead, not a finding. Reproduce it on a fork before reporting.


X: [@rDEV4224](https://x.com/rDEV4224)
