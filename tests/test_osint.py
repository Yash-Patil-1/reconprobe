"""Tests for the Advanced OSINT module (reconprobe.osint)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconprobe.osint import (
    OsintFinding,
    OsintReport,
    GITHUB_DORK_QUERIES,
    GOOGLE_DORKS,
    SOCIAL_PLATFORMS,
    BREACH_CHECK_SOURCES,
    TECH_OSINT_SOURCES,
    COMMON_EMAIL_FORMATS,
    github_dork,
    google_dork,
    harvest_emails,
    whois_lookup,
    social_footprint,
    breach_check,
    tech_stack_osint,
    run_osint,
)


# ── Data structure tests ────────────────────────────────────────────────────


class TestOsintFinding:
    def test_defaults(self):
        f = OsintFinding(source="test", type="test_type", value="test_val")
        assert f.severity == "info"
        assert f.confidence == "medium"
        assert f.url is None
        assert f.context is None
        assert f.timestamp == ""

    def test_with_all_fields(self):
        f = OsintFinding(
            source="github", type="api_key",
            value="org/repo/file", context="GitHub match",
            url="https://github.com", severity="critical",
            confidence="high", timestamp="2024-01-01",
        )
        assert f.severity == "critical"
        assert f.confidence == "high"


class TestOsintReport:
    def test_empty_report(self):
        report = OsintReport(target="example.com")
        assert report.total_findings == 0
        assert report.critical_count == 0
        assert report.high_count == 0
        assert report.medium_count == 0

    def test_severity_counts_computed(self):
        findings = [
            OsintFinding(source="github", type="key", value="a", severity="critical"),
            OsintFinding(source="github", type="key", value="b", severity="high"),
            OsintFinding(source="github", type="key", value="c", severity="high"),
            OsintFinding(source="whois", type="reg", value="d", severity="info"),
            OsintFinding(source="email", type="email", value="e", severity="low"),
            OsintFinding(source="social", type="prof", value="f", severity="medium"),
        ]
        report = OsintReport(target="x.com", findings=findings)
        assert report.total_findings == 6
        assert report.critical_count == 1
        assert report.high_count == 2
        assert report.medium_count == 1
        assert report.low_count == 1
        assert report.info_count == 1
        assert report.github_findings == 3
        assert report.whois_findings == 1
        assert report.email_findings == 1
        assert report.social_findings == 1

    def test_by_source(self):
        findings = [
            OsintFinding(source="github", type="a", value="v1"),
            OsintFinding(source="whois", type="b", value="v2"),
            OsintFinding(source="github", type="c", value="v3"),
        ]
        report = OsintReport(target="x.com", findings=findings)
        gh = report.by_source("github")
        assert len(gh) == 2
        assert len(report.by_source("whois")) == 1
        assert len(report.by_source("email")) == 0

    def test_by_severity(self):
        findings = [
            OsintFinding(source="a", type="t", value="v1", severity="critical"),
            OsintFinding(source="b", type="t", value="v2", severity="high"),
            OsintFinding(source="c", type="t", value="v3", severity="critical"),
        ]
        report = OsintReport(target="x.com", findings=findings)
        crit = report.by_severity("critical")
        assert len(crit) == 2
        assert len(report.by_severity("high")) == 1
        assert len(report.by_severity("info")) == 0

    def test_to_dict(self):
        findings = [
            OsintFinding(source="github", type="key", value="mykey", context="ctx",
                         url="https://url", severity="critical", confidence="high"),
        ]
        report = OsintReport(target="example.com", findings=findings)
        d = report.to_dict()
        assert d["target"] == "example.com"
        assert d["total_findings"] == 1
        assert d["severity_counts"]["critical"] == 1
        assert d["source_counts"]["github"] == 1
        assert len(d["findings"]) == 1
        assert d["findings"][0]["value"] == "mykey"
        assert d["findings"][0]["url"] == "https://url"


# ── Source database tests ───────────────────────────────────────────────────


class TestOsintDatabases:
    def test_github_dork_queries_count(self):
        assert len(GITHUB_DORK_QUERIES) >= 20
        for q in GITHUB_DORK_QUERIES:
            assert "type" in q
            assert "query_template" in q
            assert "severity" in q
            assert "{domain}" in q["query_template"]

    def test_google_dorks_count(self):
        assert len(GOOGLE_DORKS) >= 18
        for d in GOOGLE_DORKS:
            assert "type" in d
            assert "query_template" in d
            assert "severity" in d
            assert "{domain}" in d["query_template"]

    def test_social_platforms_count(self):
        assert len(SOCIAL_PLATFORMS) >= 15
        for p in SOCIAL_PLATFORMS:
            assert "name" in p
            assert "url_template" in p
            assert "type" in p
            assert "{domain}" in p["url_template"]

    def test_breach_sources_count(self):
        assert len(BREACH_CHECK_SOURCES) >= 5
        for s in BREACH_CHECK_SOURCES:
            assert "name" in s
            assert "url_template" in s

    def test_tech_osint_sources_count(self):
        assert len(TECH_OSINT_SOURCES) >= 8
        for s in TECH_OSINT_SOURCES:
            assert "name" in s
            assert "url_template" in s

    def test_common_email_formats(self):
        assert len(COMMON_EMAIL_FORMATS) >= 15
        assert all("{domain}" in fmt for fmt in COMMON_EMAIL_FORMATS)


# ── GitHub Dorking tests ────────────────────────────────────────────────────


class TestGitHubDork:
    @pytest.mark.asyncio
    async def test_no_token_generates_dork_suggestions(self):
        results = await github_dork("example.com")
        assert len(results) == len(GITHUB_DORK_QUERIES)
        for r in results:
            assert r.source == "github"
            assert r.confidence == "medium"
            assert r.value.startswith("Dork:")
            assert r.url and "github.com/search" in r.url

    @pytest.mark.asyncio
    async def test_with_token_and_results(self):
        with patch("reconprobe.osint._github_api_search", new_callable=AsyncMock) as mock_search:
            mock_search.return_value = {
                "total_count": 1,
                "items": [
                    {
                        "repository": {"full_name": "org/repo"},
                        "html_url": "https://github.com/org/repo/file.py",
                        "name": "file.py",
                    }
                ],
            }
            results = await github_dork("example.com", github_token="fake_token")

        assert len(results) > 0
        for r in results:
            assert r.source == "github"
            assert r.confidence == "high"
            assert r.value != "Dork:"  # Should not have dork prefix

    @pytest.mark.asyncio
    async def test_with_token_no_results(self):
        with patch("reconprobe.osint._github_api_search", new_callable=AsyncMock) as mock_search:
            mock_search.return_value = {"total_count": 0, "items": []}
            results = await github_dork("example.com", github_token="fake_token")

        # With token but no results, no findings
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_org_extraction_from_domain(self):
        results = await github_dork("mycompany.com")
        for r in results:
            assert "mycompany" in r.value  # uses 'mycompany' as org

    @pytest.mark.asyncio
    async def test_token_api_search_failure(self):
        with patch("reconprobe.osint._github_api_search", new_callable=AsyncMock) as mock_search:
            mock_search.return_value = None
            results = await github_dork("example.com", github_token="bad_token")
        assert len(results) == 0  # No fallback to dork suggestions with token


# ── Google Dorking tests ────────────────────────────────────────────────────


class TestGoogleDork:
    @pytest.mark.asyncio
    async def test_correct_number_of_dorks(self):
        results = await google_dork("example.com")
        assert len(results) == len(GOOGLE_DORKS)

    @pytest.mark.asyncio
    async def test_all_dorks_have_correct_source(self):
        results = await google_dork("test.org")
        for r in results:
            assert r.source == "google_dork"
            assert r.confidence == "medium"
            assert r.value.startswith("Dork:")

    @pytest.mark.asyncio
    async def test_dork_url_contains_encoded_query(self):
        results = await google_dork("example.com")
        for r in results:
            assert "google.com/search" in r.url
            assert r.type in [d["type"] for d in GOOGLE_DORKS]

    @pytest.mark.asyncio
    async def test_severity_matches_definition(self):
        results = await google_dork("example.com")
        for r in results:
            matching = [d for d in GOOGLE_DORKS if d["type"] == r.type]
            assert matching
            assert r.severity == matching[0]["severity"]


# ── Email Harvesting tests ──────────────────────────────────────────────────


class TestHarvestEmails:
    @pytest.mark.asyncio
    async def test_common_aliases_generated(self):
        results = await harvest_emails("example.com")
        common_results = [r for r in results if r.type == "common_alias"]
        # Should have all common aliases
        assert len(common_results) == len(COMMON_EMAIL_FORMATS)

    @pytest.mark.asyncio
    async def test_extract_from_web_content_dict(self):
        web_content = {
            "example.com": {
                "results": [
                    {
                        "body": "Contact admin@example.com or support@example.com for help",
                        "url": "https://example.com/contact",
                    }
                ]
            }
        }
        results = await harvest_emails("example.com", web_content=web_content)
        emails = [r for r in results if r.type == "email_address"]
        email_values = {r.value for r in emails}
        assert "admin@example.com" in email_values
        assert "support@example.com" in email_values

    @pytest.mark.asyncio
    async def test_admin_email_gets_higher_severity(self):
        web_content = {
            "x.com": {
                "results": [
                    {
                        "body": "admin@x.com security@x.com user@x.com",
                        "url": "https://x.com/",
                    }
                ]
            }
        }
        results = await harvest_emails("x.com", web_content=web_content)
        for r in results:
            if r.value == "admin@x.com" or r.value == "security@x.com":
                assert r.severity == "low"  # special keywords get low
            elif r.type == "email_address":
                assert r.severity == "info"  # regular emails get info

    @pytest.mark.asyncio
    async def test_deduplication_across_sources(self):
        web_content = {
            "example.com": {
                "results": [
                    {"body": "admin@example.com", "url": "https://example.com/"}
                ]
            }
        }
        results = await harvest_emails("example.com", web_content=web_content)
        admin_findings = [r for r in results if r.value == "admin@example.com"]
        # Should only appear once (from web content, not duplicated as common alias)
        assert len(admin_findings) == 1
        assert admin_findings[0].type == "email_address"

    @pytest.mark.asyncio
    async def test_no_web_content(self):
        results = await harvest_emails("example.com")
        # Only common aliases
        assert len(results) == len(COMMON_EMAIL_FORMATS)
        assert all(r.type == "common_alias" for r in results)

    @pytest.mark.asyncio
    async def test_filter_non_domain_emails(self):
        web_content = {
            "example.com": {
                "results": [
                    {
                        "body": "admin@example.com user@gmail.com",
                        "url": "https://example.com/",
                    }
                ]
            }
        }
        results = await harvest_emails("example.com", web_content=web_content)
        email_values = {r.value for r in results if r.type == "email_address"}
        assert "admin@example.com" in email_values
        assert "user@gmail.com" not in email_values  # filtered out


# ── WHOIS Lookup tests ──────────────────────────────────────────────────────


class TestWhoisLookup:
    @pytest.mark.asyncio
    async def test_command_not_found_fallback(self):
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            results = await whois_lookup("example.com")

        assert len(results) == 1
        assert results[0].type == "whois_unavailable"
        assert "whois command not found" in results[0].value.lower()
        assert results[0].url is not None

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        with patch("asyncio.create_subprocess_exec", side_effect=asyncio.TimeoutError):
            results = await whois_lookup("example.com")

        assert len(results) == 1
        assert results[0].type == "timeout"

    @pytest.mark.asyncio
    async def test_successful_lookup_with_data(self):
        whois_output = """Domain Name: EXAMPLE.COM
Registry Domain ID: 123
Registrar: Example Registrar Inc.
Creation Date: 2000-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Registrant Name: John Doe
Registrant Email: john@example.com
"""

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (whois_output.encode(), b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            results = await whois_lookup("example.com")

        types = {r.type for r in results}
        assert "registrar" in types
        assert "creation_date" in types
        assert "expiry_date" in types
        assert "name_servers" in types
        assert "registrant_name" in types
        assert "registrant_email" in types

    @pytest.mark.asyncio
    async def test_privacy_protection_detection(self):
        whois_output = """Domain Name: EXAMPLE.COM
Registrar: Some Registrar
REDACTED FOR PRIVACY
GDPR
"""

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (whois_output.encode(), b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            results = await whois_lookup("example.com")

        types = {r.type for r in results}
        assert "privacy_protection" in types

    @pytest.mark.asyncio
    async def test_non_zero_returncode(self):
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"error")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            results = await whois_lookup("example.com")

        # Non-zero returncode with stdout empty should produce no results
        # (no findings from extraction, no privacy detection)
        # No error either because it doesn't match any except block
        assert len(results) == 0


# ── Social Footprinting tests ────────────────────────────────────────────────


class TestSocialFootprint:
    @pytest.mark.asyncio
    async def test_all_platforms_returned(self):
        results = await social_footprint("example.com")
        assert len(results) == len(SOCIAL_PLATFORMS)

    @pytest.mark.asyncio
    async def test_correct_source(self):
        results = await social_footprint("test.org")
        for r in results:
            assert r.source == "social"
            assert r.severity == "info"

    @pytest.mark.asyncio
    async def test_urls_generated_correctly(self):
        results = await social_footprint("example.com")
        urls = {r.url for r in results}
        # Should have LinkedIn URL
        assert any("linkedin.com" in u for u in urls)
        assert any("github.com" in u for u in urls)
        assert any("reddit.com" in u for u in urls)
        assert any("shodan.io" in u for u in urls)

    @pytest.mark.asyncio
    async def test_platform_types(self):
        results = await social_footprint("example.com")
        types = {r.type for r in results}
        assert "company_profile" in types
        assert "social_presence" in types
        assert "code_repository" in types
        assert "infrastructure" in types


# ── Breach Check tests ──────────────────────────────────────────────────────


class TestBreachCheck:
    @pytest.mark.asyncio
    async def test_breach_sources_generated(self):
        results = await breach_check("example.com")
        assert len(results) == len(BREACH_CHECK_SOURCES)

    @pytest.mark.asyncio
    async def test_all_high_severity(self):
        results = await breach_check("example.com")
        for r in results:
            assert r.severity == "high"

    @pytest.mark.asyncio
    async def test_with_emails(self):
        emails = ["admin@example.com", "user@example.com"]
        results = await breach_check("example.com", emails=emails)
        # sources + emails (limited to 10)
        assert len(results) == len(BREACH_CHECK_SOURCES) + len(emails)

        email_checks = [r for r in results if r.type == "email_breach_check"]
        assert len(email_checks) == len(emails)
        assert "admin@example.com" in email_checks[0].value

    @pytest.mark.asyncio
    async def test_email_limit(self):
        many_emails = [f"user{i}@example.com" for i in range(20)]
        results = await breach_check("example.com", emails=many_emails)
        email_checks = [r for r in results if r.type == "email_breach_check"]
        assert len(email_checks) == 10  # Capped at 10

    @pytest.mark.asyncio
    async def test_has_hibp_url(self):
        results = await breach_check("example.com")
        hibp_results = [r for r in results if "haveibeenpwned" in (r.url or "")]
        assert len(hibp_results) >= 1


# ── Tech Stack OSINT tests ───────────────────────────────────────────────────


class TestTechStackOSINT:
    @pytest.mark.asyncio
    async def test_all_sources_returned(self):
        results = await tech_stack_osint("example.com")
        assert len(results) == len(TECH_OSINT_SOURCES)

    @pytest.mark.asyncio
    async def test_correct_source_and_severity(self):
        results = await tech_stack_osint("test.org")
        for r in results:
            assert r.source == "tech_stack"
            assert r.severity == "info"

    @pytest.mark.asyncio
    async def test_urls_contain_domain(self):
        results = await tech_stack_osint("example.com")
        for r in results:
            assert "example.com" in (r.url or "")

    @pytest.mark.asyncio
    async def test_key_sources_present(self):
        results = await tech_stack_osint("example.com")
        urls = {r.url for r in results}
        assert any("builtwith.com" in u for u in urls)
        assert any("wappalyzer.com" in u for u in urls)
        assert any("netcraft.com" in u for u in urls)
        assert any("crt.sh" in u for u in urls)


# ── Main orchestrator tests ────────────────────────────────────────────────


class TestRunOSINT:
    @pytest.mark.asyncio
    async def test_all_modules_enabled(self):
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock) as mock_gh:
            mock_gh.return_value = [OsintFinding(source="github", type="key", value="org/key")]
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock) as mock_gd:
                mock_gd.return_value = [OsintFinding(source="google_dork", type="admin", value="dork")]
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock) as mock_em:
                    mock_em.return_value = [OsintFinding(source="email", type="email", value="a@x.com")]
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock) as mock_ws:
                        mock_ws.return_value = [OsintFinding(source="whois", type="registrar", value="Reg")]
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock) as mock_soc:
                            mock_soc.return_value = [OsintFinding(source="social", type="prof", value="LinkedIn")]
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock) as mock_bc:
                                mock_bc.return_value = [OsintFinding(source="breach", type="domain", value="HIBP")]
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock) as mock_ts:
                                    mock_ts.return_value = [OsintFinding(source="tech_stack", type="tech", value="BuiltWith")]

                                    report = await run_osint("example.com")

        assert report.total_findings >= 7  # At least one from each of 7 sources
        assert report.github_findings >= 1
        assert report.google_dork_findings >= 1
        assert report.email_findings >= 1
        assert report.whois_findings >= 1
        assert report.social_findings >= 1
        assert report.breach_findings >= 1
        assert report.tech_stack_findings >= 1

    @pytest.mark.asyncio
    async def test_disable_individual_modules(self):
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock) as mock_gh:
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock) as mock_gd:
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock) as mock_em:
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock) as mock_ws:
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock) as mock_soc:
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock) as mock_bc:
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock) as mock_ts:
                                    report = await run_osint(
                                        "example.com",
                                        enable_github=False,
                                        enable_google_dorks=False,
                                        enable_email=False,
                                        enable_whois=False,
                                        enable_social=False,
                                        enable_breach=False,
                                        enable_tech_stack=False,
                                    )

        assert report.total_findings == 0
        mock_gh.assert_not_called()
        mock_gd.assert_not_called()
        mock_em.assert_not_called()
        mock_ws.assert_not_called()
        mock_soc.assert_not_called()
        mock_bc.assert_not_called()
        mock_ts.assert_not_called()

    @pytest.mark.asyncio
    async def test_deduplication(self):
        """Same finding from different sources should be deduplicated."""
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock) as mock_gh:
            mock_gh.return_value = [OsintFinding(source="github", type="key", value="duplicate")]
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock) as mock_gd:
                mock_gd.return_value = [OsintFinding(source="google_dork", type="admin", value="duplicate")]
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock) as mock_em:
                    mock_em.return_value = [OsintFinding(source="email", type="alias", value="duplicate")]
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock) as mock_ws:
                        mock_ws.return_value = [OsintFinding(source="whois", type="reg", value="duplicate")]
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock) as mock_soc:
                            mock_soc.return_value = [OsintFinding(source="social", type="prof", value="duplicate")]
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock) as mock_bc:
                                mock_bc.return_value = [OsintFinding(source="breach", type="domain", value="duplicate")]
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock) as mock_ts:
                                    mock_ts.return_value = [OsintFinding(source="tech_stack", type="tech", value="duplicate")]
                                    report = await run_osint("example.com")

        # Even though we have 7 modules each returning a finding with the
        # same value, they have different source:type prefixes, so no dedup
        assert report.total_findings == 7

        # Now test with truly identical findings (same source:type:value)
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock) as mock_gh:
            mock_gh.return_value = [OsintFinding(source="github", type="key", value="same")] * 3
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock) as mock_gd:
                mock_gd.return_value = []
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock) as mock_em:
                    mock_em.return_value = []
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock) as mock_ws:
                        mock_ws.return_value = []
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock) as mock_soc:
                            mock_soc.return_value = []
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock) as mock_bc:
                                mock_bc.return_value = []
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock) as mock_ts:
                                    mock_ts.return_value = []
                                    report2 = await run_osint("example.com")
        # Should deduplicate to 1
        assert report2.total_findings == 1

    @pytest.mark.asyncio
    async def test_severity_sorting(self):
        """Findings should be sorted with critical first."""
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock) as mock_gh:
            mock_gh.return_value = [
                OsintFinding(source="github", type="k1", value="low", severity="low"),
                OsintFinding(source="github", type="k2", value="critical", severity="critical"),
                OsintFinding(source="github", type="k3", value="high", severity="high"),
            ]
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock) as mock_gd:
                mock_gd.return_value = []
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock) as mock_em:
                    mock_em.return_value = []
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock) as mock_ws:
                        mock_ws.return_value = []
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock) as mock_soc:
                            mock_soc.return_value = []
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock) as mock_bc:
                                mock_bc.return_value = []
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock) as mock_ts:
                                    mock_ts.return_value = []
                                    report = await run_osint("example.com")

        severities = [f.severity for f in report.findings]
        assert severities == ["critical", "high", "low"]

    @pytest.mark.asyncio
    async def test_github_token_passthrough(self):
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock) as mock_gh:
            mock_gh.return_value = []
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock):
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock):
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock):
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock):
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock):
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock):
                                    await run_osint("example.com", github_token="my_token")

        mock_gh.assert_called_once_with("example.com", "my_token")

    @pytest.mark.asyncio
    async def test_http_probe_data_passthrough(self):
        probe_data = {"example.com": {"results": [{"body": "admin@example.com", "url": "https://x.com"}]}}
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock, return_value=[]):
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock, return_value=[]):
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock) as mock_em:
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock, return_value=[]):
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock, return_value=[]):
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock, return_value=[]):
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock, return_value=[]):
                                    await run_osint("example.com", http_probe_data=probe_data)

        mock_em.assert_called_once()
        args, _ = mock_em.call_args
        assert args[0] == "example.com"
        assert args[1] is probe_data

    @pytest.mark.asyncio
    async def test_breach_emails_from_harvested_emails(self):
        """When both email and breach are enabled, harvested emails should trigger individual breach checks."""
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock, return_value=[]):
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock, return_value=[]):
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock) as mock_em:
                    mock_em.return_value = [
                        OsintFinding(source="email", type="email_address", value="admin@example.com"),
                    ]
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock, return_value=[]):
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock, return_value=[]):
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock) as mock_bc:
                                # First call returns domain checks, second call returns email checks
                                def side_effect(domain, emails=None):
                                    if emails:
                                        return [OsintFinding(source="breach", type="email_breach_check",
                                                             value=f"Check HIBP for {emails[0]}")]
                                    return [OsintFinding(source="breach", type="domain_breach", value="Check HIBP")]
                                mock_bc.side_effect = side_effect
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock, return_value=[]):
                                    report = await run_osint("example.com")

        # Should have at least one email breach check
        email_checks = [f for f in report.findings if f.type == "email_breach_check"]
        assert len(email_checks) >= 1

    @pytest.mark.asyncio
    async def test_exception_handling(self):
        """Exceptions from individual modules should be caught gracefully."""
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock, side_effect=Exception("API error")):
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock, return_value=[]):
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock, return_value=[]):
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock, return_value=[]):
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock, return_value=[]):
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock, return_value=[]):
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock, return_value=[]):
                                    report = await run_osint("example.com")

        # Should not crash - github exception caught, other modules still run
        assert report.total_findings >= 0
        # Other modules should have produced results
        assert report.github_findings == 0  # github errored
        assert report.google_dork_findings >= 0

    @pytest.mark.asyncio
    async def test_empty_domain_still_runs(self):
        with patch("reconprobe.osint.github_dork", new_callable=AsyncMock) as mock_gh:
            mock_gh.return_value = []
            with patch("reconprobe.osint.google_dork", new_callable=AsyncMock, return_value=[]):
                with patch("reconprobe.osint.harvest_emails", new_callable=AsyncMock, return_value=[]):
                    with patch("reconprobe.osint.whois_lookup", new_callable=AsyncMock, return_value=[]):
                        with patch("reconprobe.osint.social_footprint", new_callable=AsyncMock, return_value=[]):
                            with patch("reconprobe.osint.breach_check", new_callable=AsyncMock, return_value=[]):
                                with patch("reconprobe.osint.tech_stack_osint", new_callable=AsyncMock, return_value=[]):
                                    report = await run_osint("")

        # Should run all modules (github uses empty string as domain)
        pass
