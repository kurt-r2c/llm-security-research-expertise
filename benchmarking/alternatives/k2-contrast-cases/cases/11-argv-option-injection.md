# Argument beginning with a dash reaches a CLI

Language: Python

## Vulnerable
```python
def archive(repo_url):
    # list form: no shell, so safe?
    subprocess.run(['git', 'clone', repo_url, DEST], check=True)
    # repo_url = "--upload-pack=touch /tmp/x"  -> option, not a URL
```

## Fixed
```python
def archive(repo_url):
    if not re.fullmatch(r'https://[\w.-]+/[\w./-]+', repo_url):
        raise ValueError
    subprocess.run(['git', 'clone', '--', repo_url, DEST], check=True)
```

Invariant: Avoiding the shell does not stop option injection; user values must be validated and separated from flags with `--`.

Look for: exec/spawn/subprocess argv arrays where a positional element is user-controlled and may start with '-'; tools with exec-style flags.
