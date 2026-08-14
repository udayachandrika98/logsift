/* Log format profiles and line parsing. */

#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "logsift.h"

/* ------------------------------------------------------------------ util */

static char *dup_range(const char *start, size_t length) {
    char *out = malloc(length + 1);
    if (!out) return NULL;
    memcpy(out, start, length);
    out[length] = '\0';
    return out;
}

static void add_field(entry_t *entry, const char *key, const char *start, size_t length) {
    if (entry->field_count >= LOGSIFT_MAX_FIELDS) return;
    if (length == 0) return;
    field_t *field = &entry->fields[entry->field_count];
    snprintf(field->key, LOGSIFT_KEY_MAX, "%s", key);
    field->value = dup_range(start, length);
    if (field->value) entry->field_count++;
}

/* ---------------------------------------------------------------- levels */

static const char *LEVEL_NAMES[LEVEL_COUNT] = {"trace", "debug", "info",
                                               "warn",  "error", "fatal"};

const char *level_name(level_t level) {
    if (level < 0 || level >= LEVEL_COUNT) return "unknown";
    return LEVEL_NAMES[level];
}

level_t level_from_string(const char *text) {
    if (!text || !*text) return LEVEL_NONE;

    char lowered[32];
    size_t i = 0;
    for (; text[i] && i < sizeof(lowered) - 1; i++) {
        lowered[i] = (char)tolower((unsigned char)text[i]);
    }
    lowered[i] = '\0';

    for (int l = 0; l < LEVEL_COUNT; l++) {
        if (strcmp(lowered, LEVEL_NAMES[l]) == 0) return (level_t)l;
    }
    if (strcmp(lowered, "warning") == 0) return LEVEL_WARN;
    if (strcmp(lowered, "err") == 0) return LEVEL_ERROR;
    if (strcmp(lowered, "critical") == 0 || strcmp(lowered, "crit") == 0 ||
        strcmp(lowered, "panic") == 0) {
        return LEVEL_FATAL;
    }
    if (strcmp(lowered, "notice") == 0) return LEVEL_INFO;
    return LEVEL_NONE;
}

/* --------------------------------------------------------------- formats */

const char *format_name(format_t format) {
    switch (format) {
        case FMT_APP: return "app";
        case FMT_NGINX: return "nginx";
        case FMT_SYSLOG: return "syslog";
        case FMT_JSON: return "json";
        default: return "auto";
    }
}

bool format_from_string(const char *text, format_t *out) {
    if (strcmp(text, "auto") == 0) { *out = FMT_AUTO; return true; }
    if (strcmp(text, "app") == 0) { *out = FMT_APP; return true; }
    if (strcmp(text, "nginx") == 0) { *out = FMT_NGINX; return true; }
    if (strcmp(text, "syslog") == 0) { *out = FMT_SYSLOG; return true; }
    if (strcmp(text, "json") == 0) { *out = FMT_JSON; return true; }
    return false;
}

/* Compiled lazily once, then reused for every line in the scan. */
typedef struct {
    regex_t regex;
    bool ready;
} lazy_regex_t;

static bool ensure_regex(lazy_regex_t *slot, const char *pattern) {
    if (slot->ready) return true;
    if (regcomp(&slot->regex, pattern, REG_EXTENDED) != 0) return false;
    slot->ready = true;
    return true;
}

#define APP_PATTERN                                                     \
    "^([0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2})"       \
    "([.,][0-9]+)?Z?[[:space:]]+"                                       \
    "\\[?([A-Za-z]+)\\]?[[:space:]]+"                                   \
    "(([A-Za-z0-9_.]+)[[:space:]]+[-:][[:space:]]+)?"                   \
    "(.*)$"

#define NGINX_PATTERN                                                   \
    "^([^[:space:]]+)[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]+)[[:space:]]+" \
    "\\[([^]]+)\\][[:space:]]+"                                         \
    "\"([A-Z]+)[[:space:]]+([^[:space:]\"]+)[^\"]*\"[[:space:]]+"       \
    "([0-9]{3})[[:space:]]+([0-9]+|-)"

#define SYSLOG_PATTERN                                                  \
    "^([A-Za-z]{3}[[:space:]]+[0-9]+[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2})[[:space:]]+" \
    "([^[:space:]]+)[[:space:]]+"                                       \
    "([A-Za-z0-9_./-]+)(\\[([0-9]+)\\])?:[[:space:]]+"                  \
    "(.*)$"

static lazy_regex_t app_re, nginx_re, syslog_re;

/* ------------------------------------------------------------ timestamps */

static time_t parse_local(struct tm *broken) {
    broken->tm_isdst = -1;
    return mktime(broken);
}

static bool parse_app_time(const char *text, size_t length, time_t *out) {
    char buffer[32];
    if (length >= sizeof(buffer)) return false;
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    for (size_t i = 0; i < length; i++) {
        if (buffer[i] == 'T') buffer[i] = ' ';
    }

    struct tm broken;
    memset(&broken, 0, sizeof(broken));
    if (!strptime(buffer, "%Y-%m-%d %H:%M:%S", &broken)) return false;
    *out = parse_local(&broken);
    return true;
}

static bool parse_nginx_time(const char *text, size_t length, time_t *out) {
    char buffer[64];
    if (length >= sizeof(buffer)) return false;
    memcpy(buffer, text, length);
    buffer[length] = '\0';

    struct tm broken;
    memset(&broken, 0, sizeof(broken));
    if (!strptime(buffer, "%d/%b/%Y:%H:%M:%S", &broken)) return false;
    *out = parse_local(&broken);
    return true;
}

static bool parse_syslog_time(const char *text, size_t length, time_t *out) {
    /* Syslog timestamps carry no year. Defaulting to 1900 would break every
     * comparison silently, so the current year is substituted. */
    char buffer[64];
    if (length >= sizeof(buffer) - 8) return false;

    time_t now = time(NULL);
    struct tm local;
    localtime_r(&now, &local);

    int written = snprintf(buffer, sizeof(buffer), "%d ", local.tm_year + 1900);
    memcpy(buffer + written, text, length);
    buffer[written + length] = '\0';

    struct tm broken;
    memset(&broken, 0, sizeof(broken));
    if (!strptime(buffer, "%Y %b %d %H:%M:%S", &broken)) return false;
    *out = parse_local(&broken);
    return true;
}

static bool parse_iso_time(const char *text, time_t *out) {
    char buffer[40];
    /* Reject rather than truncate: a silently shortened timestamp could still
     * parse and yield a plausible but wrong time. */
    size_t length = strlen(text);
    if (length >= sizeof(buffer)) return false;
    memcpy(buffer, text, length + 1);

    for (size_t i = 0; buffer[i]; i++) {
        if (buffer[i] == 'T') buffer[i] = ' ';
        if (buffer[i] == 'Z') buffer[i] = '\0';
    }
    struct tm broken;
    memset(&broken, 0, sizeof(broken));
    if (!strptime(buffer, "%Y-%m-%d %H:%M:%S", &broken)) return false;
    *out = parse_local(&broken);
    return true;
}

/* -------------------------------------------------------------- profiles */

static entry_t unparsed_entry(const char *line, size_t lineno) {
    entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.raw = strdup(line);
    entry.message = entry.raw;
    entry.lineno = lineno;
    entry.level = LEVEL_NONE;
    entry.parsed = false;
    return entry;
}

static entry_t base_entry(const char *line, size_t lineno) {
    entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.raw = strdup(line);
    entry.lineno = lineno;
    entry.level = LEVEL_NONE;
    entry.parsed = true;
    return entry;
}

static entry_t parse_app(const char *line, size_t lineno) {
    regmatch_t m[7];
    if (!ensure_regex(&app_re, APP_PATTERN) ||
        regexec(&app_re.regex, line, 7, m, 0) != 0) {
        return unparsed_entry(line, lineno);
    }

    entry_t entry = base_entry(line, lineno);
    entry.has_time = parse_app_time(line + m[1].rm_so,
                                    (size_t)(m[1].rm_eo - m[1].rm_so), &entry.timestamp);

    char level_text[32];
    size_t level_len = (size_t)(m[3].rm_eo - m[3].rm_so);
    if (level_len < sizeof(level_text)) {
        memcpy(level_text, line + m[3].rm_so, level_len);
        level_text[level_len] = '\0';
        entry.level = level_from_string(level_text);
    }

    if (m[5].rm_so != -1) {
        add_field(&entry, "logger", line + m[5].rm_so, (size_t)(m[5].rm_eo - m[5].rm_so));
    }
    entry.message = dup_range(line + m[6].rm_so, (size_t)(m[6].rm_eo - m[6].rm_so));
    return entry;
}

static entry_t parse_nginx(const char *line, size_t lineno) {
    regmatch_t m[8];
    if (!ensure_regex(&nginx_re, NGINX_PATTERN) ||
        regexec(&nginx_re.regex, line, 8, m, 0) != 0) {
        return unparsed_entry(line, lineno);
    }

    entry_t entry = base_entry(line, lineno);
    entry.has_time = parse_nginx_time(line + m[3].rm_so,
                                      (size_t)(m[3].rm_eo - m[3].rm_so), &entry.timestamp);

    add_field(&entry, "client", line + m[1].rm_so, (size_t)(m[1].rm_eo - m[1].rm_so));
    add_field(&entry, "user", line + m[2].rm_so, (size_t)(m[2].rm_eo - m[2].rm_so));
    add_field(&entry, "method", line + m[4].rm_so, (size_t)(m[4].rm_eo - m[4].rm_so));
    add_field(&entry, "path", line + m[5].rm_so, (size_t)(m[5].rm_eo - m[5].rm_so));
    add_field(&entry, "status", line + m[6].rm_so, (size_t)(m[6].rm_eo - m[6].rm_so));
    add_field(&entry, "bytes", line + m[7].rm_so, (size_t)(m[7].rm_eo - m[7].rm_so));
    entry.message = strdup(line);
    return entry;
}

static entry_t parse_syslog(const char *line, size_t lineno) {
    regmatch_t m[7];
    if (!ensure_regex(&syslog_re, SYSLOG_PATTERN) ||
        regexec(&syslog_re.regex, line, 7, m, 0) != 0) {
        return unparsed_entry(line, lineno);
    }

    entry_t entry = base_entry(line, lineno);
    entry.has_time = parse_syslog_time(line + m[1].rm_so,
                                       (size_t)(m[1].rm_eo - m[1].rm_so), &entry.timestamp);

    add_field(&entry, "host", line + m[2].rm_so, (size_t)(m[2].rm_eo - m[2].rm_so));
    add_field(&entry, "process", line + m[3].rm_so, (size_t)(m[3].rm_eo - m[3].rm_so));
    if (m[5].rm_so != -1) {
        add_field(&entry, "pid", line + m[5].rm_so, (size_t)(m[5].rm_eo - m[5].rm_so));
    }
    entry.message = dup_range(line + m[6].rm_so, (size_t)(m[6].rm_eo - m[6].rm_so));
    return entry;
}

/* Minimal flat-JSON reader: enough for newline-delimited log records, which
 * are objects of scalars. Nested values are stored as their raw text. */
static bool json_next_pair(const char **cursor, char *key, size_t key_size,
                           char *value, size_t value_size) {
    const char *p = *cursor;
    while (*p && *p != '"') {
        if (*p == '}') return false;
        p++;
    }
    if (*p != '"') return false;

    p++;
    size_t k = 0;
    while (*p && *p != '"') {
        if (k + 1 < key_size) key[k++] = *p;
        p++;
    }
    key[k] = '\0';
    if (*p != '"') return false;
    p++;

    while (*p && *p != ':') p++;
    if (*p != ':') return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;

    size_t v = 0;
    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) p++;
            if (v + 1 < value_size) value[v++] = *p;
            p++;
        }
        if (*p == '"') p++;
    } else {
        int depth = 0;
        while (*p) {
            if (*p == '[' || *p == '{') depth++;
            if (*p == ']' || *p == '}') {
                if (depth == 0) break;
                depth--;
            }
            if (*p == ',' && depth == 0) break;
            if (v + 1 < value_size) value[v++] = *p;
            p++;
        }
        while (v > 0 && (value[v - 1] == ' ' || value[v - 1] == '\t')) v--;
    }
    value[v] = '\0';

    while (*p == ' ' || *p == ',') p++;
    *cursor = p;
    return true;
}

static entry_t parse_json(const char *line, size_t lineno) {
    const char *open = strchr(line, '{');
    if (!open) return unparsed_entry(line, lineno);

    entry_t entry = base_entry(line, lineno);
    const char *cursor = open + 1;
    char key[LOGSIFT_KEY_MAX], value[512];
    bool any = false;

    while (json_next_pair(&cursor, key, sizeof(key), value, sizeof(value))) {
        any = true;
        if (!entry.has_time && (strcmp(key, "timestamp") == 0 || strcmp(key, "time") == 0 ||
                                strcmp(key, "ts") == 0 || strcmp(key, "@timestamp") == 0)) {
            entry.has_time = parse_iso_time(value, &entry.timestamp);
        } else if (entry.level == LEVEL_NONE &&
                   (strcmp(key, "level") == 0 || strcmp(key, "severity") == 0 ||
                    strcmp(key, "lvl") == 0)) {
            entry.level = level_from_string(value);
        } else if (!entry.message && (strcmp(key, "message") == 0 || strcmp(key, "msg") == 0 ||
                                      strcmp(key, "event") == 0)) {
            entry.message = strdup(value);
        } else {
            add_field(&entry, key, value, strlen(value));
        }
    }

    if (!any) {
        entry_free(&entry);
        return unparsed_entry(line, lineno);
    }
    if (!entry.message) entry.message = strdup("");
    return entry;
}

entry_t parse_line(format_t format, const char *line, size_t lineno) {
    switch (format) {
        case FMT_NGINX: return parse_nginx(line, lineno);
        case FMT_SYSLOG: return parse_syslog(line, lineno);
        case FMT_JSON: return parse_json(line, lineno);
        case FMT_APP:
        default: return parse_app(line, lineno);
    }
}

format_t detect_format(char **lines, size_t count) {
    const format_t candidates[] = {FMT_JSON, FMT_NGINX, FMT_SYSLOG, FMT_APP};
    format_t best = FMT_APP;
    size_t best_hits = 0;

    for (size_t c = 0; c < sizeof(candidates) / sizeof(candidates[0]); c++) {
        size_t hits = 0;
        for (size_t i = 0; i < count; i++) {
            if (!lines[i] || !*lines[i]) continue;
            entry_t entry = parse_line(candidates[c], lines[i], 0);
            if (entry.parsed) hits++;
            entry_free(&entry);
        }
        if (hits > best_hits) {
            best = candidates[c];
            best_hits = hits;
        }
    }
    return best;
}
