# Credential transfer state machine

```text
source active / target absent
             |
             | fresh step-up + verified source assertion + target key proof
             v
source active / target pending  ---- cancel/reconciled-not-issued --->
             |                                      source active / target revoked
             |
             | one atomic durable commit
             v
source revoked / target active
```

For provider reissue, the atomic commit is unavailable until a verified provider
receipt proves the new credential revision for the exact target and nonce. An
unknown outcome remains in the pending state and permits only signed
reconciliation; retry is not a valid transition.

The store transaction works on a private snapshot and publishes it only after
the operation succeeds. The three commit failpoints therefore leave the durable
state at `source active / target pending`, never with two active grants.
