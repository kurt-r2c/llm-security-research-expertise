# SQL built by string concatenation

Language: Java

## Vulnerable
```java
String q = "SELECT * FROM users WHERE name = '" + name + "'";
ResultSet rs = conn.createStatement().executeQuery(q);
```

## Fixed
```java
PreparedStatement ps =
    conn.prepareStatement("SELECT * FROM users WHERE name = ?");
ps.setString(1, name);
ResultSet rs = ps.executeQuery();
```

Invariant: Data reaches the query only as bound parameters, never as part of the SQL text.

Look for: +, f-strings, format, or template literals building a string passed to execute/query/raw; also ORDER BY and LIMIT fragments.
