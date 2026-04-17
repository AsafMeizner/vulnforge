# Race condition scanner

### CRITICAL: Use-after-free in event_loop()

**Location:** src/net/event.c:312

Memory is freed while another thread may still hold a reference.

```c
free(ev->buf);
// other thread still accesses ev->buf here
```

Impact: Memory corruption leading to remote code execution.
Recommendation: Use refcounting or a thread-safe free primitive.

CWE-416
CVSS: 9.1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

**[HIGH]** SQL injection at src/db/query.py:45

User-controlled parameter concatenated into query.

```python
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
```

Mitigation: Use parameterized queries.
CWE-89
