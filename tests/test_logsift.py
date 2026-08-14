import re
from datetime import datetime, timedelta

import pytest

from logsift.analyse import (
    Filter,
    buckets,
    parse_field_filters,
    parse_since,
    spikes,
    summarise,
    top,
)
from logsift.cli import main
from logsift.formats import PROFILES, Entry, detect, normalise_level, parse_stream

APP_LOG = """\
2026-08-01 10:00:00 [INFO] api.auth - user 41 signed in
2026-08-01 10:00:05 [WARN] api.rate - throttling client 10.0.0.9
2026-08-01 10:01:00 [ERROR] api.db - connection pool exhausted
2026-08-01 10:01:02 [ERROR] api.db - connection pool exhausted
2026-08-01 10:01:30 [CRITICAL] api.db - failover triggered
2026-08-01 10:02:00 [INFO] api.db - pool recovered
"""

NGINX_LOG = """\
10.0.0.1 - - [01/Aug/2026:10:00:00 +0000] "GET /health HTTP/1.1" 200 12 "-" "kube-probe"
10.0.0.2 - - [01/Aug/2026:10:00:01 +0000] "POST /api/login HTTP/1.1" 401 88 "-" "curl/8"
10.0.0.2 - - [01/Aug/2026:10:00:02 +0000] "POST /api/login HTTP/1.1" 401 88 "-" "curl/8"
10.0.0.3 - - [01/Aug/2026:10:00:03 +0000] "GET /api/orders HTTP/1.1" 500 240 "-" "app/2.1"
"""

JSON_LOG = """\
{"timestamp": "2026-08-01T10:00:00", "level": "info", "msg": "started", "service": "api"}
{"timestamp": "2026-08-01T10:00:01", "level": "error", "msg": "timeout", "service": "db"}
not json at all
"""


def entries(text, profile):
    return list(parse_stream(text.splitlines(), profile))


# --- level handling ----------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [("INFO", "info"), ("Warning", "warn"), ("ERR", "error"), ("critical", "fatal"),
     ("notice", "info"), ("nonsense", None), (None, None), ("", None)],
)
def test_level_aliases_normalise(raw, expected):
    assert normalise_level(raw) == expected


# --- parsing -----------------------------------------------------------


def test_app_format_extracts_level_logger_and_message():
    parsed = entries(APP_LOG, "app")
    assert len(parsed) == 6
    assert parsed[0].level == "info"
    assert parsed[0].fields["logger"] == "api.auth"
    assert parsed[0].message == "user 41 signed in"
    assert parsed[0].timestamp == datetime(2026, 8, 1, 10, 0, 0)


def test_critical_maps_onto_fatal():
    assert entries(APP_LOG, "app")[4].level == "fatal"


def test_nginx_format_extracts_request_fields():
    parsed = entries(NGINX_LOG, "nginx")
    assert parsed[1].fields["method"] == "POST"
    assert parsed[1].fields["path"] == "/api/login"
    assert parsed[1].fields["status"] == "401"
    assert parsed[1].fields["client"] == "10.0.0.2"


def test_json_format_promotes_unknown_keys_to_fields():
    parsed = entries(JSON_LOG, "json")
    assert parsed[1].level == "error"
    assert parsed[1].message == "timeout"
    assert parsed[1].fields["service"] == "db"


def test_a_malformed_line_is_kept_not_raised():
    parsed = entries(JSON_LOG, "json")
    assert len(parsed) == 3
    assert parsed[2].parsed is False
    assert parsed[2].raw == "not json at all"


def test_blank_lines_are_skipped():
    assert len(entries("\n\n  \n", "app")) == 0


@pytest.mark.parametrize(
    "text,expected", [(APP_LOG, "app"), (NGINX_LOG, "nginx"), (JSON_LOG, "json")]
)
def test_format_detection(text, expected):
    assert detect(text.splitlines()) == expected


def test_syslog_profile_parses_process_and_pid():
    line = "Aug  1 10:00:00 edge01 sshd[2201]: Accepted publickey for deploy"
    entry = PROFILES["syslog"].parse(line, 1)
    assert entry.fields["process"] == "sshd"
    assert entry.fields["pid"] == "2201"
    assert entry.fields["host"] == "edge01"


# --- filtering ---------------------------------------------------------


def test_min_level_keeps_that_level_and_above():
    kept = list(Filter(min_level="error").apply(entries(APP_LOG, "app")))
    assert len(kept) == 3
    assert {e.level for e in kept} == {"error", "fatal"}


def test_entries_without_a_level_survive_level_filtering():
    """A missing level is not evidence the line is unimportant."""
    unlevelled = Entry(raw="x", lineno=1, level=None)
    assert Filter(min_level="error").matches(unlevelled)


def test_grep_matches_the_raw_line():
    kept = list(Filter(pattern=re.compile("pool")).apply(entries(APP_LOG, "app")))
    assert len(kept) == 3


def test_invert_grep_excludes_matches():
    kept = list(
        Filter(pattern=re.compile("pool"), invert=True).apply(entries(APP_LOG, "app"))
    )
    assert len(kept) == 3
    assert all("pool" not in e.raw for e in kept)


def test_field_equality_filter():
    kept = list(
        Filter(field_equals={"status": "401"}).apply(entries(NGINX_LOG, "nginx"))
    )
    assert len(kept) == 2


def test_time_window_filter():
    kept = list(
        Filter(
            since=datetime(2026, 8, 1, 10, 1, 0), until=datetime(2026, 8, 1, 10, 1, 40)
        ).apply(entries(APP_LOG, "app"))
    )
    assert len(kept) == 3


def test_criteria_are_combined_with_and():
    kept = list(
        Filter(min_level="error", pattern=re.compile("failover")).apply(
            entries(APP_LOG, "app")
        )
    )
    assert len(kept) == 1


# --- helpers -----------------------------------------------------------


def test_relative_offsets_parse():
    now = datetime(2026, 8, 1, 12, 0, 0)
    assert parse_since("30m", now) == datetime(2026, 8, 1, 11, 30)
    assert parse_since("2h", now) == datetime(2026, 8, 1, 10, 0)
    assert parse_since("1d", now) == datetime(2026, 7, 31, 12, 0)


def test_iso_timestamps_parse():
    assert parse_since("2026-08-01T09:15:00", datetime.now()) == datetime(2026, 8, 1, 9, 15)


def test_unreadable_time_is_rejected():
    with pytest.raises(ValueError, match="cannot read"):
        parse_since("last tuesday", datetime.now())


def test_field_filter_needs_an_equals_sign():
    with pytest.raises(ValueError, match="KEY=VALUE"):
        parse_field_filters(["status500"])


# --- aggregation -------------------------------------------------------


def test_summary_counts_levels_and_span():
    summary = summarise(entries(APP_LOG, "app"))
    assert summary.total == 6
    assert summary.by_level["error"] == 2
    assert summary.error_count == 3  # 2 error + 1 fatal
    assert summary.error_rate == pytest.approx(0.5)
    assert summary.span == timedelta(minutes=2)


def test_summary_counts_unparsed_lines():
    assert summarise(entries(JSON_LOG, "json")).unparsed == 1


def test_summary_of_nothing_is_empty_not_an_error():
    summary = summarise([])
    assert summary.total == 0
    assert summary.error_rate == 0.0
    assert summary.span is None


def test_top_ranks_field_values():
    rows = top(entries(NGINX_LOG, "nginx"), "status")
    assert rows[0] == ("401", 2)


def test_top_ignores_entries_missing_the_field():
    assert top(entries(APP_LOG, "app"), "status") == []


def test_buckets_group_by_window():
    series = buckets(entries(APP_LOG, "app"), timedelta(minutes=1))
    assert [count for _, count in series] == [2, 3, 1]


def test_buckets_can_filter_by_level():
    series = buckets(entries(APP_LOG, "app"), timedelta(minutes=1), level="error")
    assert sum(count for _, count in series) == 3


def test_zero_width_bucket_is_rejected():
    with pytest.raises(ValueError, match="must be positive"):
        buckets(entries(APP_LOG, "app"), timedelta(0))


def test_spikes_use_the_median_so_one_outlier_does_not_hide_others():
    base = datetime(2026, 8, 1, 10, 0)
    series = [(base + timedelta(minutes=i), c) for i, c in enumerate([2, 2, 3, 60, 2, 45])]
    hot = spikes(series, factor=3.0)
    assert {count for _, count in hot} == {60, 45}


def test_spikes_need_enough_buckets_to_be_meaningful():
    base = datetime(2026, 8, 1, 10, 0)
    assert spikes([(base, 1), (base + timedelta(minutes=1), 99)]) == []


# --- CLI ---------------------------------------------------------------


def test_cli_summary_runs(tmp_path, capsys):
    path = tmp_path / "app.log"
    path.write_text(APP_LOG)
    assert main(["summary", str(path)]) == 0
    out = capsys.readouterr().out
    assert "entries   : 6" in out
    assert "error rate: 50.00%" in out


def test_cli_top_runs(tmp_path, capsys):
    path = tmp_path / "access.log"
    path.write_text(NGINX_LOG)
    assert main(["top", "status", str(path)]) == 0
    assert "401" in capsys.readouterr().out


def test_cli_show_exits_nonzero_when_nothing_matches(tmp_path):
    path = tmp_path / "app.log"
    path.write_text(APP_LOG)
    assert main(["show", str(path), "--grep", "nothing-matches-this"]) == 1


def test_cli_reports_a_bad_time_argument(tmp_path, capsys):
    path = tmp_path / "app.log"
    path.write_text(APP_LOG)
    assert main(["summary", str(path), "--since", "yesterday-ish"]) == 2
    assert "error:" in capsys.readouterr().err
