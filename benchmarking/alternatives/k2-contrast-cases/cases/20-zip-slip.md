# Archive entry name joined to the extract directory

Language: Java

## Vulnerable
```java
ZipEntry e;
while ((e = zin.getNextEntry()) != null) {
    File out = new File(destDir, e.getName());  // "../../app/x.jsp"
    Files.copy(zin, out.toPath());
}
```

## Fixed
```java
    File out = new File(destDir, e.getName()).getCanonicalFile();
    if (!out.toPath().startsWith(destDir.getCanonicalFile().toPath()))
        throw new IOException("bad entry");
    Files.copy(zin, out.toPath());
```

Invariant: Names stored inside an archive are attacker input and must be confined to the destination after resolution.

Look for: getNextEntry/extract/untar loops joining entry.name to a directory; symlink entries followed on later writes.
