# LM_VmtGetOriginal

```c
LM_API lm_address_t LM_CALL
LM_VmtGetOriginal(const lm_vmt_t *vmt,
		  lm_size_t       fn_index);
```

# Description
The function returns the original VMT function at index `fn_index` in the VMT managed by `vmt`.
If the function has not been hooked before, it returns the function pointer at that index in the VMT array.

# Parameters
 - `vmt`: The VMT manager.
 - `fn_index`: The index of the VMT function to query.

# Return Value
The original VMT function at index `fn_index` in the VMT managed by `vmt`.
