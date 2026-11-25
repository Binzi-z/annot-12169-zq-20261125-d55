"""Synthetic isolation-release drill (Python 3.12 standard library only).

This package implements the defensive machinery for the local terminal
isolation exercise described in task/PROMPT.txt:

* every allow decision binds a security *rule generation*, the *actual file
  digest* and two *independent controllers'* signatures (plus an issuer sig);
* a revoked issuer cannot fill its seat through a same-root proxy;
* a separate reconstructor rebuilds the truly-allowed set from files plus
  signature records after a "restart";
* a small exhaustive model checker covers short promote/revoke interleavings;
* a sharded 60,000-record harness compares partial revocation with full scan.

All identities, keys and artifacts are synthetic throw-away drill data.
"""

__version__ = "1.0.0"
