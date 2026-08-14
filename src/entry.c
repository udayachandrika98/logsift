/* Entry lifetime and field lookup. */

#include <stdlib.h>
#include <string.h>

#include "logsift.h"

void entry_free(entry_t *entry) {
    if (!entry) return;
    /* An unparsed entry points `message` at `raw` rather than copying it,
     * so freeing both would be a double free. */
    if (entry->message && entry->message != entry->raw) free(entry->message);
    free(entry->raw);
    for (size_t i = 0; i < entry->field_count; i++) free(entry->fields[i].value);
    memset(entry, 0, sizeof(*entry));
}

const char *entry_get(const entry_t *entry, const char *key) {
    if (strcmp(key, "level") == 0) {
        return entry->level == LEVEL_NONE ? NULL : level_name(entry->level);
    }
    if (strcmp(key, "message") == 0) return entry->message;
    for (size_t i = 0; i < entry->field_count; i++) {
        if (strcmp(entry->fields[i].key, key) == 0) return entry->fields[i].value;
    }
    return NULL;
}

void entries_init(entries_t *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void entries_push(entries_t *list, entry_t entry) {
    if (list->count == list->capacity) {
        size_t capacity = list->capacity ? list->capacity * 2 : 256;
        entry_t *grown = realloc(list->items, capacity * sizeof(entry_t));
        if (!grown) {
            entry_free(&entry);
            return;
        }
        list->items = grown;
        list->capacity = capacity;
    }
    list->items[list->count++] = entry;
}

void entries_free(entries_t *list) {
    for (size_t i = 0; i < list->count; i++) entry_free(&list->items[i]);
    free(list->items);
    entries_init(list);
}

bool read_stream(FILE *stream, format_t format, entries_t *out, format_t *chosen) {
    entries_init(out);

    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;

    /* When sniffing, buffer a sample first so the same lines can be parsed
     * again with the chosen profile rather than discarded. */
    char *sample[20];
    size_t sample_count = 0;

    if (format == FMT_AUTO) {
        while (sample_count < 20 && (length = getline(&line, &capacity, stream)) != -1) {
            while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
                line[--length] = '\0';
            }
            sample[sample_count++] = strdup(line);
        }
        format = detect_format(sample, sample_count);
    }
    if (chosen) *chosen = format;

    size_t lineno = 0;
    for (size_t i = 0; i < sample_count; i++) {
        lineno++;
        if (sample[i][0]) entries_push(out, parse_line(format, sample[i], lineno));
        free(sample[i]);
    }

    while ((length = getline(&line, &capacity, stream)) != -1) {
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
            line[--length] = '\0';
        }
        lineno++;
        if (length > 0) entries_push(out, parse_line(format, line, lineno));
    }

    free(line);
    return true;
}
