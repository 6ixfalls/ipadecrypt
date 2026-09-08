#ifndef HELPER_LOG_H
#define HELPER_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

// One logging channel: structured events on stdout. Period.
//
// Every emit() call produces exactly one line:
//     @evt event=NAME level=LVL log_seq=N log_elapsed_ms=N log_pid=N
//          log_src=FILE log_line=N log_fn=FUNCTION msg="human text" k=v ...
//
// The Go CLI parses the @evt stream for the TUI. SSH users reading
// directly see the same line  the `msg` attribute is human-readable.
//
// stderr is reserved for catastrophic helper-level failures (crashes,
// panic-style aborts). Regular progress, warnings, errors all flow
// through emit() as events.
//
// Level filter: LOG_DEBUG is suppressed entirely unless log_init was
// called with verbose=1. No duplicate output anywhere.

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3,
} log_level_t;

void log_init(int verbose);

// Redirect the event stream to a different FILE* (default: stdout). Used
// when streaming the IPA on stdout: events move to stderr so they don't
// collide with the data channel.
void log_set_stream(FILE *f);

// Attribute buffer. Stack-allocate, reuse per emit().
typedef struct {
    char buf[2048];
    int  len;
    int  overflow;
} attrs_t;

void attrs_init(attrs_t *a);
void attrs_str (attrs_t *a, const char *key, const char *val);  // auto-quoted on whitespace
void attrs_int (attrs_t *a, const char *key, long long val);
void attrs_uint(attrs_t *a, const char *key, unsigned long long val);
void attrs_hex (attrs_t *a, const char *key, unsigned long long val);  // 0xNNN
void attrs_errno(attrs_t *a, int err); // err=N error="strerror(N)"
void attrs_fmt (attrs_t *a, const char *key, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

// One event = one line on stdout. event_name is dot-namespaced
// ("image.done"). attrs may be NULL. human_fmt may be NULL (then the
// event carries only structured attrs; SSH users see only k=v).
//
// LOG_DEBUG events are dropped when verbose=0.
void log_emit_at(log_level_t level, const char *event_name, const attrs_t *a,
                 const char *file, int line, const char *function,
                 const char *human_fmt, ...)
    __attribute__((format(printf, 7, 8)));

// Capture the call site automatically. Besides making errors actionable, this
// means even old emit() calls gain source context without bespoke attributes.
#define emit(level, event_name, attrs, human_fmt, ...) \
    log_emit_at((level), (event_name), (attrs), __FILE__, __LINE__, __func__, \
                (human_fmt), ##__VA_ARGS__)

// Consistent syscall/Mach failure records. Capture errno before doing any
// formatting because stdio itself is allowed to change it.
#define LOG_ERRNO(event_name, message, ...) do { \
    int _log_errno = errno; \
    attrs_t _log_attrs; attrs_init(&_log_attrs); \
    attrs_errno(&_log_attrs, _log_errno); \
    errno = _log_errno; \
    emit(LOG_ERROR, (event_name), &_log_attrs, (message), ##__VA_ARGS__); \
    errno = _log_errno; \
} while (0)

#define LOG_MACH(event_name, kr, message, ...) do { \
    attrs_t _log_attrs; attrs_init(&_log_attrs); \
    attrs_int(&_log_attrs, "kr", (long long)(kr)); \
    emit(LOG_ERROR, (event_name), &_log_attrs, (message), ##__VA_ARGS__); \
} while (0)

#define TRACE_BEGIN(operation) do { \
    attrs_t _trace_attrs; attrs_init(&_trace_attrs); \
    attrs_str(&_trace_attrs, "operation", (operation)); \
    emit(LOG_DEBUG, "trace.begin", &_trace_attrs, NULL); \
} while (0)

#define TRACE_END(operation, result) do { \
    attrs_t _trace_attrs; attrs_init(&_trace_attrs); \
    attrs_str(&_trace_attrs, "operation", (operation)); \
    attrs_int(&_trace_attrs, "result", (long long)(result)); \
    emit(LOG_DEBUG, "trace.end", &_trace_attrs, NULL); \
} while (0)

// Free-form level-tagged messages with no stable event name. Wraps emit()
// with event="log". Useful for chatter that doesn't deserve its own name.
void log_free_form_at(log_level_t level, const char *file, int line,
                      const char *function, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
#define dbg(fmt, ...) log_free_form_at(LOG_DEBUG, __FILE__, __LINE__, __func__, (fmt), ##__VA_ARGS__)
#define inf(fmt, ...) log_free_form_at(LOG_INFO,  __FILE__, __LINE__, __func__, (fmt), ##__VA_ARGS__)
#define wrn(fmt, ...) log_free_form_at(LOG_WARN,  __FILE__, __LINE__, __func__, (fmt), ##__VA_ARGS__)
#define er(fmt, ...)  log_free_form_at(LOG_ERROR, __FILE__, __LINE__, __func__, (fmt), ##__VA_ARGS__)

// Format helper that returns a static thread-local buffer.
const char *human_bytes(unsigned long long n);

// True if the requested level would actually be emitted (cheap gate
// before expensive printf args).
int log_level_visible(log_level_t level);

#endif // HELPER_LOG_H
