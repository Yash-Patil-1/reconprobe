"""Unit tests for Phase 6: Reporting Automation (reporting.py)."""

from __future__ import annotations


import pytest

from reconprobe.reporting import (
    calculate_cvss_score,
    enrich_vulns_with_cvss,
    export_findings_csv,
    generate_executive_summary,
    generate_timeline_entries,
)


# ─── CVSS Calculator Tests ────────────────────────────────────────────────


class TestCalculateCvssScore:
    def test_critical_score(self) -> None:
        """CRITICAL: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8"""
        result = calculate_cvss_score()
        assert result["score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in result["vector_string"]

    def test_high_score(self) -> None:
        """HIGH: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L → ~8.6"""
        result = calculate_cvss_score(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="L",
            availability="L",
        )
        assert result["severity"] == "HIGH"
        assert 7.0 <= result["score"] <= 9.0

    def test_medium_score(self) -> None:
        """MEDIUM: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N → ~6.5"""
        result = calculate_cvss_score(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="L",
            availability="N",
        )
        assert result["severity"] == "MEDIUM"
        assert 4.0 <= result["score"] <= 7.0

    def test_low_score(self) -> None:
        """LOW: AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"""
        result = calculate_cvss_score(
            attack_vector="L",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="U",
            confidentiality="L",
            integrity="N",
            availability="N",
        )
        assert result["severity"] == "LOW"
        assert 0.1 <= result["score"] <= 4.0

    def test_none_score(self) -> None:
        """NONE: all metrics N"""
        result = calculate_cvss_score(
            attack_vector="P",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="N",
        )
        assert result["score"] == 0.0
        assert result["severity"] == "NONE"

    def test_changed_scope(self) -> None:
        """Changed scope (S:C) should produce a different score."""
        result_unchanged = calculate_cvss_score(scope="U")
        result_changed = calculate_cvss_score(scope="C")
        # Scope changed can amplify the score
        assert result_changed["score"] != result_unchanged["score"]

    def test_vector_string_format(self) -> None:
        result = calculate_cvss_score()
        vec = result["vector_string"]
        assert vec.startswith("CVSS:3.1/")
        assert "/AV:N" in vec
        assert "/AC:L" in vec
        assert "/PR:N" in vec

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid attack_vector"):
            calculate_cvss_score(attack_vector="X")

    def test_scores_key_present(self) -> None:
        result = calculate_cvss_score()
        scores = result["scores"]
        assert "impact" in scores
        assert "exploitability" in scores
        assert "iss" in scores
        assert scores["impact"] > 0
        assert scores["exploitability"] > 0

    def test_metrics_structure(self) -> None:
        result = calculate_cvss_score()
        metrics = result["metrics"]
        assert "attack_vector" in metrics
        assert "confidentiality" in metrics
        assert "availability" in metrics
        assert metrics["attack_vector"]["label"] == "Network"
        assert metrics["confidentiality"]["label"] == "High"


# ─── CVSS Enrichment Tests ────────────────────────────────────────────────


class TestEnrichVulnsWithCvss:
    def test_already_has_score(self) -> None:
        vulns = [{"cve_id": "CVE-2024-0001", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}]
        enriched = enrich_vulns_with_cvss(vulns)
        assert enriched[0]["cvss_score"] == 9.8

    def test_missing_score_critical(self) -> None:
        vulns = [{"cve_id": "CVE-2024-0001", "cvss_severity": "CRITICAL"}]
        enriched = enrich_vulns_with_cvss(vulns)
        assert enriched[0]["cvss_score"] == 9.8
        assert "cvss_vector" in enriched[0]
        assert "cvss_metrics" in enriched[0]

    def test_missing_score_high(self) -> None:
        vulns = [{"cve_id": "CVE-2024-0002", "cvss_severity": "HIGH"}]
        enriched = enrich_vulns_with_cvss(vulns)
        score = enriched[0]["cvss_score"]
        assert 7.0 <= score <= 9.0

    def test_missing_score_medium(self) -> None:
        vulns = [{"cve_id": "CVE-2024-0003", "cvss_severity": "MEDIUM"}]
        enriched = enrich_vulns_with_cvss(vulns)
        score = enriched[0]["cvss_score"]
        assert 4.0 <= score <= 7.0

    def test_missing_score_low(self) -> None:
        vulns = [{"cve_id": "CVE-2024-0004", "cvss_severity": "LOW"}]
        enriched = enrich_vulns_with_cvss(vulns)
        score = enriched[0]["cvss_score"]
        assert 0.1 <= score <= 4.0

    def test_empty_list(self) -> None:
        assert enrich_vulns_with_cvss([]) == []

    def test_multiple_vulns(self) -> None:
        vulns = [
            {"cve_id": "CVE-2024-0001", "cvss_severity": "CRITICAL"},
            {"cve_id": "CVE-2024-0002", "cvss_severity": "LOW"},
            {"cve_id": "CVE-2024-0003", "cvss_score": 5.0, "cvss_severity": "MEDIUM"},
        ]
        enriched = enrich_vulns_with_cvss(vulns)
        assert len(enriched) == 3
        assert enriched[0]["cvss_score"] == 9.8
        assert 0.1 <= enriched[1]["cvss_score"] <= 4.0
        assert enriched[2]["cvss_score"] == 5.0


# ─── Executive Summary Tests ──────────────────────────────────────────────


class TestGenerateExecutiveSummary:
    def _make_minimal_report(self) -> dict:
        return {
            "tool": "ReconProbe",
            "version": "0.7.0",
            "target": {"domain": "example.com"},
            "scan_info": {
                "start_time": "2026-05-25T12:00:00",
                "duration_seconds": 123.4,
            },
            "subdomain_enumeration": {"total_found": 10, "total_resolved": 8, "results": []},
            "port_scanning": {"total_hosts_scanned": 5, "hosts": []},
            "http_probing": {},
            "vulnerability_scan": {"total_cves": 3, "total_high_severity": 1},
            "ssl_tls_audit": {"results": {}},
            "subdomain_takeover": {},
            "waf_detection": {},
            "loot": {},
            "osint": {},
        }

    def test_basic_summary(self) -> None:
        report = self._make_minimal_report()
        summary = generate_executive_summary(report)
        assert "RECONPROBE EXECUTIVE SUMMARY" in summary
        assert "example.com" in summary
        assert "123.4s" in summary
        assert "Subdomains discovered" in summary

    def test_empty_report(self) -> None:
        report = {"target": {"domain": "empty.test"}, "scan_info": {}, "vulnerability_scan": {},
                   "subdomain_enumeration": {}, "port_scanning": {}, "http_probing": {},
                   "ssl_tls_audit": {}, "subdomain_takeover": {}, "waf_detection": {},
                   "loot": {}, "osint": {}}
        summary = generate_executive_summary(report)
        assert "No significant findings" in summary

    def test_critical_findings_present(self) -> None:
        report = self._make_minimal_report()
        report["subdomain_takeover"] = {"total_vulnerable": 2, "results": [{"hostname": "test.example.com"}]}
        report["loot"] = {"critical_count": 3, "items": [{"severity": "critical", "type": "API Key"}]}
        summary = generate_executive_summary(report)
        assert "🔴" in summary or "takeover" in summary
        assert "Immediately investigate" in summary

    def test_recommendations_present(self) -> None:
        report = self._make_minimal_report()
        report["ssl_tls_audit"]["results"] = {
            "example.com:443": {"total_issues": 5, "grade": "C", "weak_ciphers": [{"cipher": "RC4"}]}
        }
        summary = generate_executive_summary(report)
        assert "Recommendations" in summary
        assert "SSL/TLS" in summary or "ssl" in summary.lower()

    def test_generated_timestamp(self) -> None:
        report = self._make_minimal_report()
        summary = generate_executive_summary(report)
        assert "Report generated:" in summary


# ─── CSV Export Tests ─────────────────────────────────────────────────────


class TestExportFindingsCsv:
    def _make_report_with_data(self) -> dict:
        return {
            "target": {"domain": "test.com"},
            "scan_info": {},
            "subdomain_enumeration": {
                "total_found": 2, "total_resolved": 2,
                "results": [
                    {"hostname": "www.test.com", "ip_address": "1.2.3.4", "source": "crt.sh", "resolved": True},
                    {"hostname": "mail.test.com", "ip_address": "1.2.3.5", "source": "bruteforce", "resolved": True},
                ],
            },
            "port_scanning": {
                "hosts": [
                    {"hostname": "www.test.com", "ip_address": "1.2.3.4", "open_ports": 2, "ports": [
                        {"port": 80, "state": "open", "service": "http", "banner": "Apache"},
                        {"port": 443, "state": "open", "service": "https", "banner": "nginx"},
                    ]},
                ]
            },
            "http_probing": {},
            "vulnerability_scan": {
                "total_cves": 1, "cve_matches": [
                    {"cve_id": "CVE-2024-0001", "cvss_severity": "HIGH", "cvss_score": 8.5,
                     "affected_service": "http", "description": "Test vuln"},
                ],
                "default_credentials": [
                    {"hostname": "ftp.test.com", "service": "ftp", "port": 21, "username": "admin", "password": "admin"},
                ],
            },
            "ssl_tls_audit": {
                "results": {
                    "www.test.com:443": {
                        "weak_ciphers": [{"cipher": "RC4-SHA", "reason": "Weak cipher"}],
                        "protocols": [{"protocol": "TLS 1.0", "supported": True}],
                    }
                }
            },
            "subdomain_takeover": {},
            "waf_detection": {},
            "exploit_suggestions": {},
            "loot": {},
            "osint": {},
        }

    def test_csv_header(self) -> None:
        csv_content = export_findings_csv(self._make_report_with_data())
        assert "Category" in csv_content
        assert "Severity" in csv_content
        assert "CVE ID" in csv_content

    def test_csv_contains_subdomains(self) -> None:
        csv_content = export_findings_csv(self._make_report_with_data())
        assert "www.test.com" in csv_content
        assert "mail.test.com" in csv_content

    def test_csv_contains_ports(self) -> None:
        csv_content = export_findings_csv(self._make_report_with_data())
        assert "80/http" in csv_content or "80" in csv_content

    def test_csv_contains_cves(self) -> None:
        csv_content = export_findings_csv(self._make_report_with_data())
        assert "CVE-2024-0001" in csv_content

    def test_csv_contains_creds(self) -> None:
        csv_content = export_findings_csv(self._make_report_with_data())
        assert "admin" in csv_content

    def test_csv_contains_ssl_issues(self) -> None:
        csv_content = export_findings_csv(self._make_report_with_data())
        assert "RC4-SHA" in csv_content
        assert "TLS 1.0" in csv_content

    def test_empty_report(self) -> None:
        report = {"target": {}, "scan_info": {}, "subdomain_enumeration": {}, "port_scanning": {},
                   "http_probing": {}, "vulnerability_scan": {}, "ssl_tls_audit": {},
                   "subdomain_takeover": {}, "waf_detection": {}, "exploit_suggestions": {},
                   "loot": {}, "osint": {}}
        csv_content = export_findings_csv(report)
        # Should at least have the header row
        assert csv_content.strip() == "Category,Type,Severity,Target,Value,Description,CVSS Score,CVE ID"


# ─── Timeline Tests ───────────────────────────────────────────────────────


class TestGenerateTimeline:
    def test_empty_report(self) -> None:
        entries = generate_timeline_entries({"target": {}})
        assert isinstance(entries, list)

    def test_phases_present(self) -> None:
        report = {
            "target": {"domain": "test.com"},
            "scan_info": {"start_time": "2026-05-25T12:00:00"},
            "subdomain_enumeration": {"total_found": 5, "results": [{"hostname": "x"}]},
            "port_scanning": {"total_hosts_scanned": 1, "hosts": [{}]},
            "http_probing": {"total_alive_services": 1, "hosts": {"x": {"results": []}}},
        }
        entries = generate_timeline_entries(report)
        assert len(entries) >= 2  # subdomain + port scanning at least
        for entry in entries:
            assert "phase" in entry
            assert "status" in entry
            assert entry["status"] == "completed"
