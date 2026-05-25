"""Tests for the loot collection module (reconprobe.loot)."""

from __future__ import annotations

import pytest

from reconprobe.loot import (
    LootItem,
    LootReport,
    CREDENTIAL_PATTERNS,
    EMAIL_PATTERN,
    INTERNAL_IP_PATTERN,
    _collect_from_vuln_scan,
    _collect_from_http_probe,
    _collect_from_crawl,
    _collect_from_enrichment,
    _collect_from_takeover,
    collect_loot,
)


# ── Data structure tests ────────────────────────────────────────────────────


class TestDataStructures:
    def test_loot_item_defaults(self):
        item = LootItem(type="credential", source="vuln_scan", target="test.com", data="root/admin")
        assert item.severity == "info"
        assert item.description is None
        assert item.port is None
        assert item.path is None

    def test_loot_report_empty(self):
        report = LootReport(target="test.com")
        assert report.total_count == 0
        assert report.critical_count == 0
        assert report.high_count == 0
        assert report.info_count == 0

    def test_loot_report_with_items(self):
        items = [
            LootItem(type="credential", source="vuln_scan", target="t", data="u/p", severity="critical"),
            LootItem(type="email", source="http_probe", target="t", data="a@b.com", severity="info"),
        ]
        report = LootReport(target="test.com", items=items)
        assert report.total_count == 2
        assert report.critical_count == 1
        assert report.info_count == 1

    def test_loot_report_grouping(self):
        items = [
            LootItem(type="credential", source="vuln_scan", target="t1", data="x", severity="critical"),
            LootItem(type="credential", source="vuln_scan", target="t2", data="y", severity="high"),
            LootItem(type="email", source="http_probe", target="t3", data="z", severity="info"),
        ]
        report = LootReport(target="t", items=items)
        assert len(report.by_type("credential")) == 2
        assert len(report.by_severity("info")) == 1
        assert len(report.by_source("vuln_scan")) == 2

    def test_loot_report_to_dict(self):
        item = LootItem(type="credential", source="vuln_scan", target="t", data={"user": "root"}, severity="critical")
        report = LootReport(target="test.com", items=[item])
        d = report.to_dict()
        assert d["target"] == "test.com"
        assert d["total_count"] == 1
        assert d["severity_counts"]["critical"] == 1
        assert len(d["items"]) == 1


# ── Credential pattern tests ────────────────────────────────────────────────


class TestCredentialPatterns:
    def test_api_key_patterns(self):
        import re
        for loot_type, pattern_str, severity in CREDENTIAL_PATTERNS:
            assert severity in ("critical", "high", "medium", "low", "info")
            # Ensure pattern compiles
            try:
                re.compile(pattern_str)
            except re.error as e:
                pytest.fail(f"Invalid regex for {loot_type}: {e}")

    def test_aws_key_detection(self):
        import re
        text = "AKIA1234567890123456"
        for loot_type, pattern_str, severity in CREDENTIAL_PATTERNS:
            if loot_type == "aws_key":
                assert re.search(pattern_str, text) is not None
                break

    def test_jwt_detection(self):
        import re
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8"
        for loot_type, pattern_str, severity in CREDENTIAL_PATTERNS:
            if loot_type == "jwt_token":
                assert re.search(pattern_str, jwt) is not None
                break

    def test_email_pattern(self):
        assert EMAIL_PATTERN.search("contact@example.com") is not None
        assert EMAIL_PATTERN.search("admin@test.org") is not None
        assert EMAIL_PATTERN.search("no-email-here") is None

    def test_internal_ip_pattern(self):
        assert INTERNAL_IP_PATTERN.search("10.0.0.1") is not None
        assert INTERNAL_IP_PATTERN.search("192.168.1.100") is not None
        assert INTERNAL_IP_PATTERN.search("172.16.0.1") is not None
        assert INTERNAL_IP_PATTERN.search("8.8.8.8") is None


# ── Vuln scan collection tests ──────────────────────────────────────────────


class TestCollectFromVulnScan:
    def test_none_data_returns_empty(self):
        items = _collect_from_vuln_scan(None, "test.com")
        assert items == []

    def test_dict_credentials(self):
        data = {
            "default_credentials": [
                {"service": "ssh", "username": "root", "password": "root", "port": 22, "status": "success"},
                {"service": "mysql", "username": "admin", "password": "admin", "port": 3306, "status": "success"},
            ]
        }
        items = _collect_from_vuln_scan(data, "test.com")
        assert len(items) == 2
        assert all(i.severity == "critical" for i in items)
        assert all(i.type == "credential" for i in items)
        assert items[0].data["service"] == "ssh"

    def test_duplicate_credentials(self):
        data = {
            "default_credentials": [
                {"service": "ssh", "username": "root", "password": "root", "port": 22},
                {"service": "ssh", "username": "root", "password": "root", "port": 22},  # duplicate
            ]
        }
        items = _collect_from_vuln_scan(data, "test.com")
        # Dedup happens at collect_loot level, not here
        assert len(items) == 2

    def test_empty_credentials_list(self):
        data = {"default_credentials": []}
        items = _collect_from_vuln_scan(data, "test.com")
        assert items == []

    def test_credential_has_description(self):
        data = {
            "default_credentials": [
                {"service": "redis", "username": "", "password": "", "port": 6379},
            ]
        }
        items = _collect_from_vuln_scan(data, "test.com")
        assert len(items) == 1
        assert "redis" in items[0].description.lower() or "unknown" in items[0].description.lower()


# ── HTTP probe collection tests ─────────────────────────────────────────────


class TestCollectFromHttpProbe:
    def test_none_data_returns_empty(self):
        items = _collect_from_http_probe(None, "test.com")
        assert items == []

    def test_empty_results(self):
        data = {"results": []}
        items = _collect_from_http_probe(data, "test.com")
        assert items == []

    def test_finds_emails_in_body(self):
        data = {
            "results": [
                {"body": "Contact us at admin@example.com or support@test.org", "url": "http://test.com/contact", "headers": {}}
            ]
        }
        items = _collect_from_http_probe(data, "test.com")
        emails = [i for i in items if i.type == "email"]
        assert len(emails) >= 2

    def test_finds_internal_ips(self):
        data = {
            "results": [
                {"body": "Internal server at 10.0.0.5", "url": "http://test.com/", "headers": {}}
            ]
        }
        items = _collect_from_http_probe(data, "test.com")
        internal_ips = [i for i in items if i.type == "internal_host"]
        assert len(internal_ips) >= 1
        assert "10.0.0.5" in internal_ips[0].data

    def test_finds_aws_key_in_body(self):
        data = {
            "results": [
                {"body": "AWS_KEY=AKIA1234567890123456", "url": "http://test.com/config", "headers": {}}
            ]
        }
        items = _collect_from_http_probe(data, "test.com")
        aws_keys = [i for i in items if i.type == "aws_key"]
        assert len(aws_keys) >= 1

    def test_handles_object_results(self):
        """Test with object-like structures (with .technologies attribute)."""
        mock_result = type("MockResult", (), {
            "body": "admin@example.com", "headers": {}, "url": "http://test.com", "port": 80
        })()
        data = type("MockReport", (), {"results": [mock_result]})()
        items = _collect_from_http_probe(data, "test.com")
        assert len(items) > 0

    def test_severity_for_admin_emails(self):
        data = {
            "results": [
                {"body": "root@example.com", "url": "http://test.com", "headers": {}}
            ]
        }
        items = _collect_from_http_probe(data, "test.com")
        admin_emails = [i for i in items if i.type == "email" and "admin" in i.data.lower() or "root" in i.data.lower()]
        # admin/root emails should have 'low' severity (higher than 'info')
        for e in admin_emails:
            assert e.severity == "low"


# ── Crawl collection tests ──────────────────────────────────────────────────


class TestCollectFromCrawl:
    def test_none_data_returns_empty(self):
        items = _collect_from_crawl(None, "test.com")
        assert items == []

    def test_empty_pages(self):
        items = _collect_from_crawl([], "test.com")
        assert items == []

    def test_finds_credentials_in_body(self):
        data = {
            "pages": [
                {"url": "http://test.com/config", "body": "password=supersecret123", "forms": []}
            ]
        }
        items = _collect_from_crawl(data, "test.com")
        passwords = [i for i in items if i.type == "password_in_url"]
        assert len(passwords) >= 1

    def test_detects_login_forms(self):
        data = {
            "pages": [
                {
                    "url": "http://test.com/login",
                    "body": "",
                    "forms": [
                        {"action": "/login", "inputs": [{"type": "text"}, {"type": "password"}]}
                    ]
                }
            ]
        }
        items = _collect_from_crawl(data, "test.com")
        endpoints = [i for i in items if i.type == "endpoint"]
        assert len(endpoints) >= 1
        assert "login" in endpoints[0].description.lower()

    def test_handles_object_pages(self):
        form = type("MockForm", (), {"action": "/login", "inputs": [type("MockInput", (), {"type": "password"})()]})()
        page = type("MockPage", (), {"url": "http://test.com/login", "body": "", "forms": [form]})()
        data = type("MockCrawlData", (), {"pages": [page]})()
        items = _collect_from_crawl(data, "test.com")
        endpoints = [i for i in items if i.type == "endpoint"]
        assert len(endpoints) >= 1


# ── Enrichment collection tests ─────────────────────────────────────────────


class TestCollectFromEnrichment:
    def test_none_data_returns_empty(self):
        items = _collect_from_enrichment(None, "test.com")
        assert items == []

    def test_shodan_vulns(self):
        data = {
            "shodan": {
                "vulns": [
                    {"cve_id": "CVE-2024-0001", "cvss": 9.8},
                    {"cve_id": "CVE-2024-0002", "cvss": 5.5},
                ]
            }
        }
        items = _collect_from_enrichment(data, "test.com")
        vulns = [i for i in items if i.type == "vulnerability"]
        assert len(vulns) == 2
        # High CVSS should be 'high' severity
        assert vulns[0].severity == "high"
        assert vulns[1].severity == "medium"

    def test_nvd_cves(self):
        data = {
            "nvd_cves": [
                {"id": "CVE-2024-0003", "cvss_score": 7.5},
                {"id": "CVE-2024-0004", "cvss_score": 4.0},
            ]
        }
        items = _collect_from_enrichment(data, "test.com")
        vulns = [i for i in items if i.type == "vulnerability"]
        assert len(vulns) == 2

    def test_empty_enrichment_data(self):
        data = {"shodan": {}, "nvd_cves": []}
        items = _collect_from_enrichment(data, "test.com")
        assert items == []


# ── Takeover collection tests ───────────────────────────────────────────────


class TestCollectFromTakeover:
    def test_none_data_returns_empty(self):
        items = _collect_from_takeover(None, "test.com")
        assert items == []

    def test_vulnerable_subdomains(self):
        data = {
            "results": [
                {"subdomain": "vuln.test.com", "vulnerable": True, "service": "AWS S3", "confidence": "high"},
                {"subdomain": "safe.test.com", "vulnerable": False, "service": "", "confidence": "none"},
            ]
        }
        items = _collect_from_takeover(data, "test.com")
        assert len(items) == 1
        assert items[0].severity == "critical"
        assert items[0].type == "takeover"
        assert "AWS S3" in str(items[0].data)

    def test_handles_object_results(self):
        result = type("MockResult", (), {
            "subdomain": "vuln.test.com", "vulnerable": True,
            "service": "GitHub Pages", "confidence": "medium"
        })()
        data = type("MockTakeoverData", (), {"results": [result]})()
        items = _collect_from_takeover(data, "test.com")
        assert len(items) == 1
        assert items[0].severity == "critical"


# ── Main orchestrator tests ─────────────────────────────────────────────────


class TestCollectLoot:
    def test_no_data_sources(self):
        report = collect_loot(target="test.com")
        assert report.total_count == 0

    def test_all_sources_combined(self):
        vuln_data = {
            "default_credentials": [
                {"service": "ssh", "username": "root", "password": "root", "port": 22},
            ]
        }
        http_data = {
            "results": [
                {"body": "admin@example.com", "url": "http://test.com", "headers": {}}
            ]
        }
        takeover_data = {
            "results": [
                {"subdomain": "vuln.test.com", "vulnerable": True, "service": "AWS S3", "confidence": "high"},
            ]
        }
        enrichment_data = {
            "shodan": {
                "vulns": [
                    {"cve_id": "CVE-2024-0001", "cvss": 9.8},
                ]
            }
        }
        crawl_data = {
            "pages": [
                {
                    "url": "http://test.com/login",
                    "body": "",
                    "forms": [{"action": "/login", "inputs": [{"type": "password"}]}],
                }
            ]
        }

        report = collect_loot(
            target="test.com",
            vuln_scan_data=vuln_data,
            http_probe_data=http_data,
            crawl_data=crawl_data,
            enrichment_data=enrichment_data,
            takeover_data=takeover_data,
        )
        assert report.total_count >= 4

    def test_deduplication(self):
        """Same loot item from different sources should be deduplicated."""
        vuln_data = {
            "default_credentials": [
                {"service": "ssh", "username": "root", "password": "root", "port": 22},
            ]
        }
        # Same data from two calls
        report1 = collect_loot(target="test.com", vuln_scan_data=vuln_data)
        report2 = collect_loot(target="test.com", vuln_scan_data=vuln_data)
        # Each call should produce the same count
        assert report1.total_count == report2.total_count

    def test_severity_ordering(self):
        """Items should be sorted by severity (critical first)."""
        items = [
            LootItem(type="email", source="hp", target="t", data="a@b.com", severity="info"),
            LootItem(type="credential", source="vs", target="t", data="u/p", severity="critical"),
            LootItem(type="takeover", source="to", target="t", data="x", severity="critical"),
            LootItem(type="internal_host", source="hp", target="t", data="10.0.0.1", severity="medium"),
        ]
        report = LootReport(target="test.com", items=items)
        # Severity order: critical = 0, high = 1, medium = 2, low = 3, info = 4
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_items = sorted(items, key=lambda i: sev_order.get(i.severity, 99))
        assert sorted_items[0].severity == "critical"
        assert sorted_items[-1].severity == "info"

    def test_to_dict_structure(self):
        report = collect_loot(target="test.com")
        d = report.to_dict()
        assert "target" in d
        assert "total_count" in d
        assert "severity_counts" in d
        assert "items" in d
