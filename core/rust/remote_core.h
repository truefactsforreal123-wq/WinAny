#ifndef REMOTE_CORE_H
#define REMOTE_CORE_H
#ifdef __cplusplus
extern "C" {
#endif
/* request must be a valid, NUL-terminated UTF-8 JSON string. */
char *remote_core_call(const char *request);
/* Free exactly once, only with a pointer returned by remote_core_call. */
void remote_core_free(char *response);
#ifdef __cplusplus
}
#endif
#endif
