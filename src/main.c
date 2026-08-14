/* logsift command line interface. */

#define _XOPEN_SOURCE 700

#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "logsift.h"

#define LOGSIFT_VERSION "0.2.0"

static void usage(void) {
    fputs(
        "logsift -- filter, summarise and find spikes in log files\n"
        "\n"
        "usage:\n"
        "  logsift show    [options] [FILE]\n"
        "  logsift summary [options] [FILE]\n"
        "  logsift top KEY [options] [FILE]\n"
        "  logsift rate    [options] [FILE]\n"
        "\n"
        "FILE defaults to stdin, so logsift composes in a pipeline.\n"
        "\n"
        "shared options:\n"
        "  -f, --format FORMAT   app | nginx | syslog | json | auto (default: auto)\n"
        "  -l, --level LEVEL     keep this level and above\n"
        "  -g, --grep REGEX      raw line must match\n"
        "  -v, --invert          invert --grep\n"
        "      --case-sensitive  make --grep case sensitive\n"
        "      --since WHEN      ISO time, or an offset like 30m / 2h / 1d\n"
        "      --until WHEN      ISO time, or an offset like 30m / 2h / 1d\n"
        "      --field KEY=VALUE require a field value\n"
        "      --verbose         report the detected format\n"
        "\n"
        "show:  -n, --limit N        stop after N lines\n"
        "top:   -n, --limit N        rows to show (default 10)\n"
        "rate:  -w, --window SECS    bucket width (default 60)\n"
        "       --at-level LEVEL     only count this level and above\n"
        "       --spike-factor F     spike threshold (default 3.0)\n",
        stdout);
}

typedef struct {
    format_t format;
    const char *level;
    const char *grep;
    bool invert;
    bool case_sensitive;
    const char *since;
    const char *until;
    const char *field;
    bool verbose;
    long limit;
    long window;
    const char *at_level;
    double spike_factor;
    const char *file;
    const char *key;
} options_t;

static bool build_filter(const options_t *options, filter_t *filter) {
    filter_init(filter);

    if (options->level) {
        filter->min_level = level_from_string(options->level);
        if (filter->min_level == LEVEL_NONE) {
            fprintf(stderr, "error: unknown level '%s'\n", options->level);
            return false;
        }
    }
    if (options->grep) {
        int flags = REG_EXTENDED | REG_NOSUB;
        if (!options->case_sensitive) flags |= REG_ICASE;
        if (regcomp(&filter->pattern, options->grep, flags) != 0) {
            fprintf(stderr, "error: bad regex '%s'\n", options->grep);
            return false;
        }
        filter->has_pattern = true;
        filter->invert = options->invert;
    }

    time_t now = time(NULL);
    if (options->since) {
        if (!parse_time_arg(options->since, now, &filter->since)) {
            fprintf(stderr, "error: cannot read '%s' as a time -- use ISO format or an "
                            "offset like 30m\n", options->since);
            return false;
        }
        filter->has_since = true;
    }
    if (options->until) {
        if (!parse_time_arg(options->until, now, &filter->until)) {
            fprintf(stderr, "error: cannot read '%s' as a time -- use ISO format or an "
                            "offset like 30m\n", options->until);
            return false;
        }
        filter->has_until = true;
    }
    if (options->field) {
        const char *equals = strchr(options->field, '=');
        if (!equals) {
            fprintf(stderr, "error: field filter '%s' must be in KEY=VALUE form\n",
                    options->field);
            return false;
        }
        size_t key_length = (size_t)(equals - options->field);
        if (key_length >= LOGSIFT_KEY_MAX) key_length = LOGSIFT_KEY_MAX - 1;
        memcpy(filter->field_key, options->field, key_length);
        filter->field_key[key_length] = '\0';
        filter->field_value = strdup(equals + 1);
        filter->has_field = true;
    }
    return true;
}

static FILE *open_input(const options_t *options) {
    if (!options->file || strcmp(options->file, "-") == 0) return stdin;
    FILE *stream = fopen(options->file, "r");
    if (!stream) fprintf(stderr, "error: cannot read %s\n", options->file);
    return stream;
}

static void print_time(time_t when, char *buffer, size_t size) {
    struct tm broken;
    localtime_r(&when, &broken);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &broken);
}

/* ------------------------------------------------------------- commands */

static int cmd_show(const options_t *options, const entries_t *entries,
                    const filter_t *filter) {
    long matched = 0;
    for (size_t i = 0; i < entries->count; i++) {
        if (!filter_matches(filter, &entries->items[i])) continue;
        matched++;
        if (options->limit && matched > options->limit) break;
        puts(entries->items[i].raw);
    }
    return matched ? 0 : 1;
}

static int cmd_summary(const entries_t *entries, const filter_t *filter) {
    summary_t summary;
    summarise(entries, filter, &summary);

    if (summary.total == 0) {
        puts("no matching entries");
        return 1;
    }

    printf("entries   : %zu\n", summary.total);
    if (summary.unparsed) {
        printf("unparsed  : %zu (%.1f%%)\n", summary.unparsed,
               100.0 * (double)summary.unparsed / (double)summary.total);
    }
    if (summary.has_span) {
        char first[32], last[32];
        print_time(summary.first, first, sizeof(first));
        print_time(summary.last, last, sizeof(last));
        long span = (long)(summary.last - summary.first);
        printf("first     : %s\n", first);
        printf("last      : %s\n", last);
        printf("span      : %ld:%02ld:%02ld\n", span / 3600, (span % 3600) / 60, span % 60);
    }
    printf("error rate: %.2f%%\n",
           100.0 * (double)summary_error_count(&summary) / (double)summary.total);

    puts("\nby level:");
    /* Print in descending count order, like the level histogram it replaces. */
    bool shown[LEVEL_COUNT] = {false};
    for (int printed = 0; printed < LEVEL_COUNT; printed++) {
        int best = -1;
        for (int l = 0; l < LEVEL_COUNT; l++) {
            if (shown[l] || summary.by_level[l] == 0) continue;
            if (best < 0 || summary.by_level[l] > summary.by_level[best]) best = l;
        }
        if (best < 0) break;
        shown[best] = true;

        double share = (double)summary.by_level[best] / (double)summary.total;
        printf("  %-5s  %7zu  %5.1f%%  ", level_name((level_t)best),
               summary.by_level[best], share * 100.0);
        for (int b = 0; b < (int)(share * 40); b++) putchar('#');
        putchar('\n');
    }
    if (summary.no_level) {
        printf("  %-5s  %7zu\n", "none", summary.no_level);
    }
    return 0;
}

static int cmd_top(const options_t *options, const entries_t *entries,
                   const filter_t *filter) {
    top_t top;
    size_t limit = options->limit > 0 ? (size_t)options->limit : 10;
    top_values(entries, filter, options->key, limit, &top);

    if (top.count == 0) {
        fprintf(stderr, "no entries carry a '%s' field\n", options->key);
        top_free(&top);
        return 1;
    }

    size_t total = 0, width = 0;
    for (size_t i = 0; i < top.count; i++) {
        total += top.rows[i].count;
        size_t length = strlen(top.rows[i].value);
        if (length > width) width = length;
    }

    printf("top %zu by %s:\n", top.count, options->key);
    for (size_t i = 0; i < top.count; i++) {
        printf("  %-*s  %7zu  %5.1f%%\n", (int)width, top.rows[i].value, top.rows[i].count,
               100.0 * (double)top.rows[i].count / (double)total);
    }
    top_free(&top);
    return 0;
}

static int cmd_rate(const options_t *options, const entries_t *entries,
                    const filter_t *filter) {
    level_t at_level = LEVEL_NONE;
    if (options->at_level) {
        at_level = level_from_string(options->at_level);
        if (at_level == LEVEL_NONE) {
            fprintf(stderr, "error: unknown level '%s'\n", options->at_level);
            return 2;
        }
    }

    buckets_t buckets;
    long window = options->window > 0 ? options->window : 60;
    if (!bucket_series(entries, filter, window, at_level, &buckets)) {
        fprintf(stderr, "no timestamped entries to plot\n");
        buckets_free(&buckets);
        return 1;
    }

    size_t peak = 0;
    for (size_t i = 0; i < buckets.count; i++) {
        if (buckets.items[i].count > peak) peak = buckets.items[i].count;
    }

    for (size_t i = 0; i < buckets.count; i++) {
        char when[32];
        print_time(buckets.items[i].start, when, sizeof(when));
        printf("  %s  %6zu  ", when, buckets.items[i].count);
        int bar = (int)((double)buckets.items[i].count / (double)peak * 40.0);
        for (int b = 0; b < (bar > 0 ? bar : 1); b++) putchar('#');
        putchar('\n');
    }

    size_t *indices = malloc(buckets.count * sizeof(size_t));
    size_t spikes = indices ? find_spikes(&buckets, options->spike_factor, indices,
                                          buckets.count) : 0;
    int status = 0;
    if (spikes) {
        printf("\n%zu spike(s) at >= %.1fx the median bucket:\n", spikes,
               options->spike_factor);
        for (size_t i = 0; i < spikes; i++) {
            char when[32];
            print_time(buckets.items[indices[i]].start, when, sizeof(when));
            printf("  %s  %zu\n", when, buckets.items[indices[i]].count);
        }
        status = 2;
    }

    free(indices);
    buckets_free(&buckets);
    return status;
}

/* ---------------------------------------------------------------- driver */

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 2;
    }

    const char *command = argv[1];
    if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0 ||
        strcmp(command, "help") == 0) {
        usage();
        return 0;
    }
    if (strcmp(command, "--version") == 0) {
        puts("logsift " LOGSIFT_VERSION);
        return 0;
    }

    bool is_show = strcmp(command, "show") == 0;
    bool is_summary = strcmp(command, "summary") == 0;
    bool is_top = strcmp(command, "top") == 0;
    bool is_rate = strcmp(command, "rate") == 0;
    if (!is_show && !is_summary && !is_top && !is_rate) {
        fprintf(stderr, "unknown command '%s'\n\n", command);
        usage();
        return 2;
    }

    options_t options;
    memset(&options, 0, sizeof(options));
    options.format = FMT_AUTO;
    options.window = 60;
    options.spike_factor = 3.0;

    int argi = 2;
    if (is_top) {
        if (argc < 3) {
            fprintf(stderr, "top needs a field name\n");
            return 2;
        }
        options.key = argv[2];
        argi = 3;
    }

    static struct option longopts[] = {
        {"format", required_argument, 0, 'f'},
        {"level", required_argument, 0, 'l'},
        {"grep", required_argument, 0, 'g'},
        {"invert", no_argument, 0, 'v'},
        {"limit", required_argument, 0, 'n'},
        {"window", required_argument, 0, 'w'},
        {"case-sensitive", no_argument, 0, 1},
        {"since", required_argument, 0, 2},
        {"until", required_argument, 0, 3},
        {"field", required_argument, 0, 4},
        {"verbose", no_argument, 0, 5},
        {"at-level", required_argument, 0, 6},
        {"spike-factor", required_argument, 0, 7},
        {0, 0, 0, 0}};

    /* Shift the subcommand (and top's KEY) out of the way for getopt. */
    int shifted_argc = argc - argi + 1;
    char **shifted_argv = malloc((size_t)(shifted_argc + 1) * sizeof(char *));
    if (!shifted_argv) return 2;
    shifted_argv[0] = argv[0];
    for (int i = 0; i < shifted_argc - 1; i++) shifted_argv[i + 1] = argv[argi + i];
    shifted_argv[shifted_argc] = NULL;

    int opt, index = 0;
    optind = 1;
    while ((opt = getopt_long(shifted_argc, shifted_argv, "f:l:g:vn:w:", longopts,
                              &index)) != -1) {
        switch (opt) {
            case 'f':
                if (!format_from_string(optarg, &options.format)) {
                    fprintf(stderr, "error: unknown format '%s'\n", optarg);
                    free(shifted_argv);
                    return 2;
                }
                break;
            case 'l': options.level = optarg; break;
            case 'g': options.grep = optarg; break;
            case 'v': options.invert = true; break;
            case 'n': options.limit = strtol(optarg, NULL, 10); break;
            case 'w': options.window = strtol(optarg, NULL, 10); break;
            case 1: options.case_sensitive = true; break;
            case 2: options.since = optarg; break;
            case 3: options.until = optarg; break;
            case 4: options.field = optarg; break;
            case 5: options.verbose = true; break;
            case 6: options.at_level = optarg; break;
            case 7: options.spike_factor = strtod(optarg, NULL); break;
            default: free(shifted_argv); usage(); return 2;
        }
    }
    if (optind < shifted_argc) options.file = shifted_argv[optind];

    filter_t filter;
    if (!build_filter(&options, &filter)) {
        filter_free(&filter);
        free(shifted_argv);
        return 2;
    }

    FILE *stream = open_input(&options);
    if (!stream) {
        filter_free(&filter);
        free(shifted_argv);
        return 2;
    }

    entries_t entries;
    format_t chosen = options.format;
    read_stream(stream, options.format, &entries, &chosen);
    if (stream != stdin) fclose(stream);
    if (options.verbose) fprintf(stderr, "# format: %s\n", format_name(chosen));

    int status = 0;
    if (is_show) status = cmd_show(&options, &entries, &filter);
    else if (is_summary) status = cmd_summary(&entries, &filter);
    else if (is_top) status = cmd_top(&options, &entries, &filter);
    else status = cmd_rate(&options, &entries, &filter);

    entries_free(&entries);
    filter_free(&filter);
    free(shifted_argv);
    return status;
}
