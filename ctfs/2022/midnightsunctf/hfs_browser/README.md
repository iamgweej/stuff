# The Bugs

Dangling pointer here:

```cpp 
DUK_INTERNAL duk_ret_t duk_bi_typedarray_midnight(duk_hthread *thr) {
	duk_hbufobj *h_bufobj = NULL;
	duk_hbuffer_dynamic * buf = NULL;

	h_bufobj = duk__require_bufobj_this(thr);
	DUK_ASSERT(h_bufobj != NULL);
	DUK_HBUFOBJ_ASSERT_VALID(h_bufobj);

	buf = (duk_hbuffer_dynamic*)h_bufobj->buf;
	if (buf == NULL) {
		return 0;
	}

	if (buf->curr_alloc != NULL) {
		duk_free(thr, buf->curr_alloc);
	}

	return 0;
}
```

Exploitation overview (stupid way):

* Create a `Uint8Array` the size of a `duk_hbuffer_dynamic`.
* Cause a dangling pointer.
* Allocate another buffer, making it return the freed buffer as its `duk_hbuffer_dynamic` header.
* Leak a heap pointer.
* Leak `libc` addresss from got.
* Acheive write-what-where.
* Find the `my_fatal` function address on the heap space, to determine the address of the `duk_heap` structure.
* Override allocation virtual pointer to be `/bin/sh`.
* Success.

There are others (more stable/pie bypass) ways to exploit this bug, but this was the simplest one.
