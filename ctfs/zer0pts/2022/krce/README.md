# The Bugs

Pretty straightforward access out of bound:

```cpp
long buffer_edit(int32_t index, char *data, int32_t size) {
  if (index >= BUF_NUM) // BUG - what if index < 0?
    return -EINVAL;

  if (!buffer[index])
    return -EINVAL;

  if (copy_from_user(buffer[index], data, size))
    return -EINVAL;

  return 0;
}

long buffer_show(int32_t index, char *data, int32_t size) {
  if (index >= BUF_NUM) // BUG - what if index < 0?
    return -EINVAL;

  if (!buffer[index])
    return -EINVAL;

  if (copy_to_user(data, buffer[index], size))
    return -EINVAL;

  return 0;
}
```

Exploitation overview:

* Get `buffer[0]` to point to `buffer[1]`, by writing to the `__this_module` pointer stored in the `module_fops` structure.
* Use that to get generic write-what-where and read-what-where primitives in the kernel.
* Find `init_task` and our `task_struct`.
* Copy creds from `init_task` to our `task_struct`.
* Find the usermode addresses of our binary, libc and the stack.
* Construct a rop chain on the usermode stack to call `system("/bin/sh")`.
* Victory!
