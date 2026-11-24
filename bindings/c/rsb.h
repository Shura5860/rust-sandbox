/* rust-sandbox C ABI header (`librsb_ffi.so`) */
#ifndef RSB_FFI_H
#define RSB_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns static NUL-terminated version string. Do NOT free. */
const char *rsb_version(void);

/* Returns host kernel Landlock ABI version, or -1 if unavailable. */
int32_t rsb_landlock_abi(void);

/*
 * Run a sandboxed command and return a newly allocated JSON report string.
 * Free the returned pointer with `rsb_string_free`.
 */
char *rsb_exec_json(
    const char *program,
    const char *const *argv,
    size_t argc,
    const char *rw_dir,
    uint64_t timeout_ms,
    int32_t allow_network,
    int32_t use_namespaces
);

/*
 * Run a sandboxed command configured by a full `sandbox.toml` profile string
 * (supports ro, ro_data, rw, ephemeral_cow, limits, allow_syscalls, hostname, rootfs).
 * Free the returned pointer with `rsb_string_free`. Thread-safe.
 */
char *rsb_exec_profile_toml_json(
    const char *profile_toml,
    const char *program,
    const char *const *argv,
    size_t argc
);

/* Free a string returned by `rsb_exec_json`, `rsb_exec_profile_toml_json`, or `rsb_zygote_exec_json`. */
void rsb_string_free(char *ptr);

/*
 * Opaque handle for a pre-warmed Python Zygote fork server.
 *
 * Thread safety: `rsb_zygote_pool_t` is NOT thread-safe. Callers must serialize
 * concurrent calls to `rsb_zygote_exec_json` and `rsb_zygote_free` on the same
 * handle (e.g. with a mutex). Separate handles may be used concurrently from
 * different threads. `rsb_version`, `rsb_landlock_abi`, `rsb_exec_json`, and
 * `rsb_string_free` are thread-safe.
 */
typedef struct rsb_zygote_pool rsb_zygote_pool_t;

rsb_zygote_pool_t *rsb_zygote_start_python(int32_t allow_network, int32_t use_namespaces);
char *rsb_zygote_exec_json(rsb_zygote_pool_t *pool, const char *code, uint64_t timeout_ms);
void rsb_zygote_free(rsb_zygote_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* RSB_FFI_H */
