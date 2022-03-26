# The Bugs

The child bug is a classical stack bof:

```cpp
long getlong(const char *msg) {
  char buf[32];
  print(msg);
  if (read(0, buf, 322) < 0) // BUG
    exit(1);
  return atol(buf);
}
```

The parent bug is the "weird" state the parent is in when `malloc` fails, which leads to a write-what-where (trivially):

```cpp
void parent_note(int c2p, int p2c, int cpid) {
  // ...

  while (1) {
    // ...

    switch (req.cmd)
    {
      /* Create new buffer */
      case NEW: {
        if (req.size > 2800) {
          /* Invalid size*/
          RESPONSE(-1);
          break;
        }

        /* Allocate new buffer */
        old = buffer;
        if (!(buffer = (uint64_t*)malloc(req.size * sizeof(uint64_t)))) {
          /* Memory error */
          size = -1; // BUG - infinite length
          RESPONSE(-1);
          break;
        }
        // ...
      }

      /* Set value */
      case SET: {
        // ...
      }

      /* Get value */
      case GET: {
        // ...
      }

      default:
        // ...
    }
  }
}
```

So we need to get `malloc` to fail in the parent process. This might seem impossible since we dont have a memory leak or arbitrary length allocations, but we can limit the memory usage of the parent process using the `prlimit` syscall (which is not blacklisted by the seccomp).
