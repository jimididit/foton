# Public/Baseline

Normalized snapshots of **stable** configuration (services, tasks, autoruns, accounts,
drivers, software, firewall, shares, listeners, hardening values, certs, key binary hashes).

Exclude volatile state (PIDs, live connections, uptime, sessions) or diffs become noise.

**Provider model:** one file per surface declaring record type, identity key, collect
scriptblock, compared vs ignored fields. Adding a surface = one new provider file, not a
edit to a giant function.

`New-FotonBaseline` captures. `Compare-FotonBaseline` diffs field-by-field and feeds
findings. Always state snapshot times and that a diff proves **change between observations**,
not when or who.

Capture may run on a live host. Diff must run fully offline on two package/baseline files.
