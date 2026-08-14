/* Filtering and aggregation over parsed entries. */

#define _XOPEN_SOURCE 700

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "logsift.h"

/* ---------------------------------------------------------------- filter */

void filter_init(filter_t *filter) {
    memset(filter, 0, sizeof(*filter));
    filter->min_level = LEVEL_NONE;
}

void filter_free(filter_t *filter) {
    if (filter->has_pattern) regfree(&filter->pattern);
    free(filter->field_value);
    filter->field_value = NULL;
    filter->has_pattern = false;
    filter->has_field = false;
}

bool filter_matches(const filter_t *filter, const entry_t *entry) {
    /* Entries with no level survive level filtering -- a missing level is
     * not proof the line is unimportant, and dropping them loses data. */
    if (filter->min_level != LEVEL_NONE && entry->level != LEVEL_NONE &&
        entry->level < filter->min_level) {
        return false;
    }

    if (filter->has_since && entry->has_time && entry->timestamp < filter->since) return false;
    if (filter->has_until && entry->has_time && entry->timestamp > filter->until) return false;

    if (filter->has_field) {
        const char *value = entry_get(entry, filter->field_key);
        if (!value || strcmp(value, filter->field_value) != 0) return false;
    }

    if (filter->has_pattern) {
        bool hit = regexec(&filter->pattern, entry->raw, 0, NULL, 0) == 0;
        if (hit == filter->invert) return false;
    }

    return true;
}

bool parse_time_arg(const char *text, time_t now, time_t *out) {
    size_t length = strlen(text);
    if (length >= 2 && length <= 8) {
        char unit = text[length - 1];
        if (unit == 's' || unit == 'm' || unit == 'h' || unit == 'd') {
            bool numeric = true;
            for (size_t i = 0; i + 1 < length; i++) {
                if (!isdigit((unsigned char)text[i])) { numeric = false; break; }
            }
            if (numeric) {
                long amount = strtol(text, NULL, 10);
                long scale = unit == 's' ? 1 : unit == 'm' ? 60 : unit == 'h' ? 3600 : 86400;
                *out = now - amount * scale;
                return true;
            }
        }
    }

    char buffer[40];
    /* Reject rather than truncate -- a shortened timestamp can still parse
     * and yield a plausible but wrong time. */
    if (length >= sizeof(buffer)) return false;
    memcpy(buffer, text, length + 1);

    for (size_t i = 0; buffer[i]; i++) {
        if (buffer[i] == 'T') buffer[i] = ' ';
    }
    struct tm broken;
    memset(&broken, 0, sizeof(broken));
    if (!strptime(buffer, "%Y-%m-%d %H:%M:%S", &broken)) return false;
    broken.tm_isdst = -1;
    *out = mktime(&broken);
    return true;
}

/* --------------------------------------------------------------- summary */

void summarise(const entries_t *entries, const filter_t *filter, summary_t *out) {
    memset(out, 0, sizeof(*out));

    for (size_t i = 0; i < entries->count; i++) {
        const entry_t *entry = &entries->items[i];
        if (filter && !filter_matches(filter, entry)) continue;

        out->total++;
        if (!entry->parsed) out->unparsed++;
        if (entry->level == LEVEL_NONE) {
            out->no_level++;
        } else {
            out->by_level[entry->level]++;
        }
        if (entry->has_time) {
            if (!out->has_span || entry->timestamp < out->first) out->first = entry->timestamp;
            if (!out->has_span || entry->timestamp > out->last) out->last = entry->timestamp;
            out->has_span = true;
        }
    }
}

size_t summary_error_count(const summary_t *summary) {
    return summary->by_level[LEVEL_ERROR] + summary->by_level[LEVEL_FATAL];
}

/* ------------------------------------------------------------------- top */

static int compare_top(const void *a, const void *b) {
    const top_row_t *left = a, *right = b;
    if (left->count != right->count) return left->count < right->count ? 1 : -1;
    return strcmp(left->value, right->value);
}

void top_values(const entries_t *entries, const filter_t *filter, const char *key,
                size_t limit, top_t *out) {
    top_row_t *rows = NULL;
    size_t count = 0, capacity = 0;

    for (size_t i = 0; i < entries->count; i++) {
        const entry_t *entry = &entries->items[i];
        if (filter && !filter_matches(filter, entry)) continue;

        const char *value = entry_get(entry, key);
        if (!value || !*value) continue;

        size_t found = count;
        for (size_t r = 0; r < count; r++) {
            if (strcmp(rows[r].value, value) == 0) { found = r; break; }
        }
        if (found < count) {
            rows[found].count++;
            continue;
        }
        if (count == capacity) {
            capacity = capacity ? capacity * 2 : 32;
            top_row_t *grown = realloc(rows, capacity * sizeof(top_row_t));
            if (!grown) break;
            rows = grown;
        }
        rows[count].value = strdup(value);
        rows[count].count = 1;
        count++;
    }

    /* qsort with a NULL base is undefined even when count is 0, and glibc's
     * prototype marks the argument non-null -- UBSan flags it. */
    if (count > 1) qsort(rows, count, sizeof(top_row_t), compare_top);

    if (limit && count > limit) {
        for (size_t i = limit; i < count; i++) free(rows[i].value);
        count = limit;
    }
    out->rows = rows;
    out->count = count;
}

void top_free(top_t *top) {
    for (size_t i = 0; i < top->count; i++) free(top->rows[i].value);
    free(top->rows);
    top->rows = NULL;
    top->count = 0;
}

/* --------------------------------------------------------------- buckets */

static int compare_buckets(const void *a, const void *b) {
    const bucket_t *left = a, *right = b;
    if (left->start == right->start) return 0;
    return left->start < right->start ? -1 : 1;
}

static int compare_sizes(const void *a, const void *b) {
    size_t left = *(const size_t *)a, right = *(const size_t *)b;
    if (left == right) return 0;
    return left < right ? -1 : 1;
}

bool bucket_series(const entries_t *entries, const filter_t *filter, long window,
                   level_t at_level, buckets_t *out) {
    out->items = NULL;
    out->count = 0;
    if (window <= 0) return false;

    size_t capacity = 0;

    for (size_t i = 0; i < entries->count; i++) {
        const entry_t *entry = &entries->items[i];
        if (filter && !filter_matches(filter, entry)) continue;
        if (!entry->has_time) continue; /* cannot be placed on a timeline */
        if (at_level != LEVEL_NONE && entry->level < at_level) continue;

        time_t floored = entry->timestamp - (entry->timestamp % window);

        size_t found = out->count;
        for (size_t b = 0; b < out->count; b++) {
            if (out->items[b].start == floored) { found = b; break; }
        }
        if (found < out->count) {
            out->items[found].count++;
            continue;
        }
        if (out->count == capacity) {
            capacity = capacity ? capacity * 2 : 64;
            bucket_t *grown = realloc(out->items, capacity * sizeof(bucket_t));
            if (!grown) return false;
            out->items = grown;
        }
        out->items[out->count].start = floored;
        out->items[out->count].count = 1;
        out->count++;
    }

    if (out->count > 1) qsort(out->items, out->count, sizeof(bucket_t), compare_buckets);
    return out->count > 0;
}

void buckets_free(buckets_t *buckets) {
    free(buckets->items);
    buckets->items = NULL;
    buckets->count = 0;
}

size_t find_spikes(const buckets_t *buckets, double factor, size_t *indices,
                   size_t max_indices) {
    if (buckets->count < 3) return 0;

    size_t *counts = malloc(buckets->count * sizeof(size_t));
    if (!counts) return 0;
    for (size_t i = 0; i < buckets->count; i++) counts[i] = buckets->items[i].count;
    qsort(counts, buckets->count, sizeof(size_t), compare_sizes);

    double median = (double)counts[buckets->count / 2];
    free(counts);
    if (median <= 0.0) median = 1.0;

    size_t found = 0;
    for (size_t i = 0; i < buckets->count && found < max_indices; i++) {
        if ((double)buckets->items[i].count >= median * factor) indices[found++] = i;
    }
    return found;
}
