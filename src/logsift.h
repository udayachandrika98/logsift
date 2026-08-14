/* logsift -- filter, summarise and find spikes in log files.
 *
 * Everything here is C11 plus POSIX (regex.h, strptime). No third-party
 * dependencies.
 */

#ifndef LOGSIFT_H
#define LOGSIFT_H

#include <regex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

/* ---------------------------------------------------------------- levels */

/* Ordered by severity so filtering can be "this level and above". */
typedef enum {
    LEVEL_NONE = -1,
    LEVEL_TRACE = 0,
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_WARN,
    LEVEL_ERROR,
    LEVEL_FATAL,
    LEVEL_COUNT
} level_t;

/* Maps aliases too: warning->warn, err->error, critical/crit/panic->fatal. */
level_t level_from_string(const char *text);
const char *level_name(level_t level);

/* ---------------------------------------------------------------- fields */

#define LOGSIFT_MAX_FIELDS 12
#define LOGSIFT_KEY_MAX 32

typedef struct {
    char key[LOGSIFT_KEY_MAX];
    char *value; /* owned */
} field_t;

/* ---------------------------------------------------------------- entries */

typedef struct {
    char *raw;     /* owned, the original line */
    char *message; /* points into raw's arena or owned; see entry_free */
    size_t lineno;
    time_t timestamp; /* 0 when the line carried no usable time */
    bool has_time;
    level_t level;
    bool parsed;
    field_t fields[LOGSIFT_MAX_FIELDS];
    size_t field_count;
} entry_t;

void entry_free(entry_t *entry);
const char *entry_get(const entry_t *entry, const char *key);

/* A growable entry list. */
typedef struct {
    entry_t *items;
    size_t count;
    size_t capacity;
} entries_t;

void entries_init(entries_t *list);
void entries_push(entries_t *list, entry_t entry);
void entries_free(entries_t *list);

/* --------------------------------------------------------------- formats */

typedef enum { FMT_AUTO, FMT_APP, FMT_NGINX, FMT_SYSLOG, FMT_JSON } format_t;

const char *format_name(format_t format);
bool format_from_string(const char *text, format_t *out);

/* Parses one line. Never fails: an unrecognised line comes back with
 * parsed=false and the raw text as its message, so nothing is silently
 * dropped from a scan. */
entry_t parse_line(format_t format, const char *line, size_t lineno);

/* Guesses the format from a sample, most specific first. */
format_t detect_format(char **lines, size_t count);

/* Reads a whole stream into `out`, parsing as it goes. */
bool read_stream(FILE *stream, format_t format, entries_t *out, format_t *chosen);

/* ---------------------------------------------------------------- filter */

typedef struct {
    level_t min_level;
    regex_t pattern;
    bool has_pattern;
    bool invert;
    time_t since;
    bool has_since;
    time_t until;
    bool has_until;
    char field_key[LOGSIFT_KEY_MAX];
    char *field_value; /* owned */
    bool has_field;
} filter_t;

void filter_init(filter_t *filter);
void filter_free(filter_t *filter);
bool filter_matches(const filter_t *filter, const entry_t *entry);

/* Accepts an ISO timestamp or a relative offset like 30m / 2h / 1d. */
bool parse_time_arg(const char *text, time_t now, time_t *out);

/* -------------------------------------------------------------- analysis */

typedef struct {
    size_t total;
    size_t unparsed;
    size_t by_level[LEVEL_COUNT];
    size_t no_level;
    time_t first;
    time_t last;
    bool has_span;
} summary_t;

void summarise(const entries_t *entries, const filter_t *filter, summary_t *out);
size_t summary_error_count(const summary_t *summary);

/* Most common values of a field. Caller frees with top_free. */
typedef struct {
    char *value; /* owned */
    size_t count;
} top_row_t;

typedef struct {
    top_row_t *rows;
    size_t count;
} top_t;

void top_values(const entries_t *entries, const filter_t *filter, const char *key,
                size_t limit, top_t *out);
void top_free(top_t *top);

/* Fixed-width time buckets. */
typedef struct {
    time_t start;
    size_t count;
} bucket_t;

typedef struct {
    bucket_t *items;
    size_t count;
} buckets_t;

bool bucket_series(const entries_t *entries, const filter_t *filter, long window,
                   level_t at_level, buckets_t *out);
void buckets_free(buckets_t *buckets);

/* Buckets at or above `factor` times the median. The median is used rather
 * than the mean so one enormous spike cannot raise the baseline and mask
 * the smaller ones around it. */
size_t find_spikes(const buckets_t *buckets, double factor, size_t *indices,
                   size_t max_indices);

#endif /* LOGSIFT_H */
