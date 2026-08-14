#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "logsift.h"

static const char *APP_LOG[] = {
    "2026-08-01 10:00:00 [INFO] api.auth - user 41 signed in",
    "2026-08-01 10:00:05 [WARN] api.rate - throttling client 10.0.0.9",
    "2026-08-01 10:01:00 [ERROR] api.db - connection pool exhausted",
    "2026-08-01 10:01:02 [ERROR] api.db - connection pool exhausted",
    "2026-08-01 10:01:30 [CRITICAL] api.db - failover triggered",
    "2026-08-01 10:02:00 [INFO] api.db - pool recovered",
};

static const char *NGINX_LOG[] = {
    "10.0.0.1 - - [01/Aug/2026:10:00:00 +0000] \"GET /health HTTP/1.1\" 200 12 \"-\" \"kube-probe\"",
    "10.0.0.2 - - [01/Aug/2026:10:00:01 +0000] \"POST /api/login HTTP/1.1\" 401 88 \"-\" \"curl/8\"",
    "10.0.0.2 - - [01/Aug/2026:10:00:02 +0000] \"POST /api/login HTTP/1.1\" 401 88 \"-\" \"curl/8\"",
    "10.0.0.3 - - [01/Aug/2026:10:00:03 +0000] \"GET /api/orders HTTP/1.1\" 500 240 \"-\" \"app/2.1\"",
};

static const char *JSON_LOG[] = {
    "{\"timestamp\": \"2026-08-01T10:00:00\", \"level\": \"info\", \"msg\": \"started\", \"service\": \"api\"}",
    "{\"timestamp\": \"2026-08-01T10:00:01\", \"level\": \"error\", \"msg\": \"timeout\", \"service\": \"db\"}",
    "not json at all",
};

static void load(entries_t *entries, format_t format, const char **lines, size_t count) {
    entries_init(entries);
    for (size_t i = 0; i < count; i++) {
        entries_push(entries, parse_line(format, lines[i], i + 1));
    }
}

static size_t count_matching(const entries_t *entries, const filter_t *filter) {
    size_t total = 0;
    for (size_t i = 0; i < entries->count; i++) {
        if (filter_matches(filter, &entries->items[i])) total++;
    }
    return total;
}

/* ---------------------------------------------------------------- levels */

TEST(level_aliases_normalise) {
    CHECK(level_from_string("INFO") == LEVEL_INFO);
    CHECK(level_from_string("Warning") == LEVEL_WARN);
    CHECK(level_from_string("ERR") == LEVEL_ERROR);
    CHECK(level_from_string("critical") == LEVEL_FATAL);
    CHECK(level_from_string("panic") == LEVEL_FATAL);
    CHECK(level_from_string("notice") == LEVEL_INFO);
    CHECK(level_from_string("nonsense") == LEVEL_NONE);
    CHECK(level_from_string("") == LEVEL_NONE);
    CHECK(level_from_string(NULL) == LEVEL_NONE);
}

TEST(levels_are_ordered_by_severity) {
    CHECK(LEVEL_TRACE < LEVEL_DEBUG);
    CHECK(LEVEL_DEBUG < LEVEL_INFO);
    CHECK(LEVEL_INFO < LEVEL_WARN);
    CHECK(LEVEL_WARN < LEVEL_ERROR);
    CHECK(LEVEL_ERROR < LEVEL_FATAL);
}

/* --------------------------------------------------------------- parsing */

TEST(app_format_extracts_level_logger_and_message) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    CHECK_EQ(entries.count, 6);
    CHECK(entries.items[0].level == LEVEL_INFO);
    CHECK_STR(entry_get(&entries.items[0], "logger"), "api.auth");
    CHECK_STR(entries.items[0].message, "user 41 signed in");
    CHECK(entries.items[0].has_time);
    entries_free(&entries);
}

TEST(critical_maps_onto_fatal) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    CHECK(entries.items[4].level == LEVEL_FATAL);
    entries_free(&entries);
}

TEST(nginx_format_extracts_request_fields) {
    entries_t entries;
    load(&entries, FMT_NGINX, NGINX_LOG, 4);
    CHECK_STR(entry_get(&entries.items[1], "method"), "POST");
    CHECK_STR(entry_get(&entries.items[1], "path"), "/api/login");
    CHECK_STR(entry_get(&entries.items[1], "status"), "401");
    CHECK_STR(entry_get(&entries.items[1], "client"), "10.0.0.2");
    entries_free(&entries);
}

TEST(json_format_promotes_unknown_keys_to_fields) {
    entries_t entries;
    load(&entries, FMT_JSON, JSON_LOG, 3);
    CHECK(entries.items[1].level == LEVEL_ERROR);
    CHECK_STR(entries.items[1].message, "timeout");
    CHECK_STR(entry_get(&entries.items[1], "service"), "db");
    entries_free(&entries);
}

TEST(a_malformed_line_is_kept_not_dropped) {
    entries_t entries;
    load(&entries, FMT_JSON, JSON_LOG, 3);
    CHECK_EQ(entries.count, 3);
    CHECK_FALSE(entries.items[2].parsed);
    CHECK_STR(entries.items[2].raw, "not json at all");
    entries_free(&entries);
}

TEST(syslog_profile_parses_process_and_pid) {
    const char *line = "Aug  1 10:00:00 edge01 sshd[2201]: Accepted publickey for deploy";
    entry_t entry = parse_line(FMT_SYSLOG, line, 1);
    CHECK(entry.parsed);
    CHECK_STR(entry_get(&entry, "process"), "sshd");
    CHECK_STR(entry_get(&entry, "pid"), "2201");
    CHECK_STR(entry_get(&entry, "host"), "edge01");
    entry_free(&entry);
}

TEST(syslog_gets_the_current_year_not_1900) {
    const char *line = "Aug  1 10:00:00 edge01 sshd[2201]: hello";
    entry_t entry = parse_line(FMT_SYSLOG, line, 1);
    CHECK(entry.has_time);
    struct tm broken;
    localtime_r(&entry.timestamp, &broken);
    CHECK(broken.tm_year + 1900 > 2000);
    entry_free(&entry);
}

TEST(format_detection) {
    char *app[6], *nginx[4], *json[3];
    for (int i = 0; i < 6; i++) app[i] = strdup(APP_LOG[i]);
    for (int i = 0; i < 4; i++) nginx[i] = strdup(NGINX_LOG[i]);
    for (int i = 0; i < 3; i++) json[i] = strdup(JSON_LOG[i]);

    CHECK(detect_format(app, 6) == FMT_APP);
    CHECK(detect_format(nginx, 4) == FMT_NGINX);
    CHECK(detect_format(json, 3) == FMT_JSON);

    for (int i = 0; i < 6; i++) free(app[i]);
    for (int i = 0; i < 4; i++) free(nginx[i]);
    for (int i = 0; i < 3; i++) free(json[i]);
}

/* ------------------------------------------------------------- filtering */

TEST(min_level_keeps_that_level_and_above) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    filter_t filter;
    filter_init(&filter);
    filter.min_level = LEVEL_ERROR;
    CHECK_EQ(count_matching(&entries, &filter), 3);
    filter_free(&filter);
    entries_free(&entries);
}

TEST(entries_without_a_level_survive_level_filtering) {
    /* A missing level is not evidence the line is unimportant. */
    entry_t entry = parse_line(FMT_APP, "no timestamp or level here", 1);
    filter_t filter;
    filter_init(&filter);
    filter.min_level = LEVEL_ERROR;
    CHECK(entry.level == LEVEL_NONE);
    CHECK(filter_matches(&filter, &entry));
    filter_free(&filter);
    entry_free(&entry);
}

TEST(grep_matches_the_raw_line) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    filter_t filter;
    filter_init(&filter);
    CHECK_EQ(regcomp(&filter.pattern, "pool", REG_EXTENDED | REG_NOSUB), 0);
    filter.has_pattern = true;
    CHECK_EQ(count_matching(&entries, &filter), 3);
    filter_free(&filter);
    entries_free(&entries);
}

TEST(invert_grep_excludes_matches) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    filter_t filter;
    filter_init(&filter);
    CHECK_EQ(regcomp(&filter.pattern, "pool", REG_EXTENDED | REG_NOSUB), 0);
    filter.has_pattern = true;
    filter.invert = true;
    CHECK_EQ(count_matching(&entries, &filter), 3);
    filter_free(&filter);
    entries_free(&entries);
}

TEST(field_equality_filter) {
    entries_t entries;
    load(&entries, FMT_NGINX, NGINX_LOG, 4);
    filter_t filter;
    filter_init(&filter);
    snprintf(filter.field_key, LOGSIFT_KEY_MAX, "status");
    filter.field_value = strdup("401");
    filter.has_field = true;
    CHECK_EQ(count_matching(&entries, &filter), 2);
    filter_free(&filter);
    entries_free(&entries);
}

TEST(criteria_are_combined_with_and) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    filter_t filter;
    filter_init(&filter);
    filter.min_level = LEVEL_ERROR;
    CHECK_EQ(regcomp(&filter.pattern, "failover", REG_EXTENDED | REG_NOSUB), 0);
    filter.has_pattern = true;
    CHECK_EQ(count_matching(&entries, &filter), 1);
    filter_free(&filter);
    entries_free(&entries);
}

/* ----------------------------------------------------------- time parsing */

TEST(relative_offsets_parse) {
    time_t now = 1000000;
    time_t out;
    CHECK(parse_time_arg("30m", now, &out));
    CHECK_EQ((long)(now - out), 1800L);
    CHECK(parse_time_arg("2h", now, &out));
    CHECK_EQ((long)(now - out), 7200L);
    CHECK(parse_time_arg("1d", now, &out));
    CHECK_EQ((long)(now - out), 86400L);
}

TEST(iso_timestamps_parse) {
    time_t out;
    CHECK(parse_time_arg("2026-08-01T09:15:00", time(NULL), &out));
    struct tm broken;
    localtime_r(&out, &broken);
    CHECK_EQ(broken.tm_year + 1900, 2026);
    CHECK_EQ(broken.tm_hour, 9);
}

TEST(unreadable_time_is_rejected) {
    time_t out;
    CHECK_FALSE(parse_time_arg("last tuesday", time(NULL), &out));
}

/* ----------------------------------------------------------- aggregation */

TEST(summary_counts_levels_and_span) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    summary_t summary;
    summarise(&entries, NULL, &summary);
    CHECK_EQ(summary.total, 6);
    CHECK_EQ(summary.by_level[LEVEL_ERROR], 2);
    CHECK_EQ(summary_error_count(&summary), 3); /* 2 error + 1 fatal */
    CHECK_EQ((long)(summary.last - summary.first), 120L);
    entries_free(&entries);
}

TEST(summary_counts_unparsed_lines) {
    entries_t entries;
    load(&entries, FMT_JSON, JSON_LOG, 3);
    summary_t summary;
    summarise(&entries, NULL, &summary);
    CHECK_EQ(summary.unparsed, 1);
    entries_free(&entries);
}

TEST(summary_of_nothing_is_empty_not_an_error) {
    entries_t entries;
    entries_init(&entries);
    summary_t summary;
    summarise(&entries, NULL, &summary);
    CHECK_EQ(summary.total, 0);
    CHECK_EQ(summary_error_count(&summary), 0);
    CHECK_FALSE(summary.has_span);
    entries_free(&entries);
}

TEST(top_ranks_field_values) {
    entries_t entries;
    load(&entries, FMT_NGINX, NGINX_LOG, 4);
    top_t top;
    top_values(&entries, NULL, "status", 10, &top);
    CHECK(top.count >= 1);
    CHECK_STR(top.rows[0].value, "401");
    CHECK_EQ(top.rows[0].count, 2);
    top_free(&top);
    entries_free(&entries);
}

TEST(top_ignores_entries_missing_the_field) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    top_t top;
    top_values(&entries, NULL, "status", 10, &top);
    CHECK_EQ(top.count, 0);
    top_free(&top);
    entries_free(&entries);
}

TEST(top_respects_the_limit) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    top_t top;
    top_values(&entries, NULL, "logger", 2, &top);
    CHECK_EQ(top.count, 2);
    top_free(&top);
    entries_free(&entries);
}

TEST(buckets_group_by_window) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    buckets_t buckets;
    CHECK(bucket_series(&entries, NULL, 60, LEVEL_NONE, &buckets));
    size_t total = 0;
    for (size_t i = 0; i < buckets.count; i++) total += buckets.items[i].count;
    CHECK_EQ(total, 6);
    CHECK_EQ(buckets.count, 3);
    buckets_free(&buckets);
    entries_free(&entries);
}

TEST(buckets_can_filter_by_level) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    buckets_t buckets;
    CHECK(bucket_series(&entries, NULL, 60, LEVEL_ERROR, &buckets));
    size_t total = 0;
    for (size_t i = 0; i < buckets.count; i++) total += buckets.items[i].count;
    CHECK_EQ(total, 3);
    buckets_free(&buckets);
    entries_free(&entries);
}

TEST(zero_width_bucket_is_rejected) {
    entries_t entries;
    load(&entries, FMT_APP, APP_LOG, 6);
    buckets_t buckets;
    CHECK_FALSE(bucket_series(&entries, NULL, 0, LEVEL_NONE, &buckets));
    buckets_free(&buckets);
    entries_free(&entries);
}

TEST(spikes_use_the_median_so_one_outlier_does_not_hide_others) {
    bucket_t items[6];
    size_t counts[6] = {2, 2, 3, 60, 2, 45};
    for (int i = 0; i < 6; i++) {
        items[i].start = 1000 + i * 60;
        items[i].count = counts[i];
    }
    buckets_t buckets = {items, 6};

    size_t indices[6];
    size_t found = find_spikes(&buckets, 3.0, indices, 6);
    CHECK_EQ(found, 2);
    CHECK_EQ(buckets.items[indices[0]].count, 60);
    CHECK_EQ(buckets.items[indices[1]].count, 45);
}

TEST(spikes_need_enough_buckets_to_be_meaningful) {
    bucket_t items[2] = {{1000, 1}, {1060, 99}};
    buckets_t buckets = {items, 2};
    size_t indices[2];
    CHECK_EQ(find_spikes(&buckets, 3.0, indices, 2), 0);
}

TEST(a_flat_series_has_no_spikes) {
    bucket_t items[5];
    for (int i = 0; i < 5; i++) {
        items[i].start = 1000 + i * 60;
        items[i].count = 10;
    }
    buckets_t buckets = {items, 5};
    size_t indices[5];
    CHECK_EQ(find_spikes(&buckets, 3.0, indices, 5), 0);
}

int main(void) { return check_run_all(); }
