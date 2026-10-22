# DECOY: shell=True with only server-chosen values

Language: Python

## Looks vulnerable
```python
REPORTS = {'daily': 'daily.sh', 'weekly': 'weekly.sh'}
def run(kind, user):
    script = REPORTS[kind]            # KeyError for anything else
    subprocess.run(f"{SCRIPTS}/{script} --uid {int(user.id)}", shell=True)
```

Shell plus interpolation pattern-matches as command injection, but the fragments are a dict value and int(). It is a hardening smell, not an exploitable bug, unless the map or int() is removed.

Invariant: Every interpolated fragment is either a constant from a closed map or coerced to an integer, so no metacharacter can arrive.

Look for: shell=True and f-strings are only a finding when an attacker-influenced string survives to the command line; trace each fragment's source and type.
