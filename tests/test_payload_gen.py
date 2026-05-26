"""Tests for the payload generation module (reconprobe.payload_gen)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from reconprobe.payload_gen import (
    Payload,
    PayloadReport,
    generate_bash_reverse_shell,
    generate_python_reverse_shell,
    generate_python3_reverse_shell,
    generate_powershell_reverse_shell,
    generate_netcat_reverse_shell,
    generate_php_reverse_shell,
    generate_perl_reverse_shell,
    generate_ruby_reverse_shell,
    generate_ncat_ssl_reverse_shell,
    generate_socat_reverse_shell,
    generate_awk_reverse_shell,
    generate_telnet_reverse_shell,
    try_msfvenom_generate,
    generate_payload,
    generate_all_payloads,
)


# ── Data structure tests ────────────────────────────────────────────────────


class TestDataStructures:
    def test_payload_defaults(self):
        p = Payload(type="bash", command="bash -i", listener_command="nc -lvnp 4444")
        assert p.encoded is False
        assert p.encoded_command is None
        assert p.lhost == "127.0.0.1"
        assert p.lport == 4444
        assert p.description is None

    def test_payload_with_all_fields(self):
        p = Payload(
            type="python", command="python3 -c 'code'",
            listener_command="rlwrap nc -lvnp 8888",
            encoded=True, encoded_command="encoded_version",
            lhost="10.0.0.1", lport=8888,
            description="Python reverse shell",
        )
        assert p.encoded is True
        assert p.encoded_command == "encoded_version"
        assert p.lhost == "10.0.0.1"
        assert p.lport == 8888

    def test_payload_report_empty(self):
        report = PayloadReport(target="test.com")
        assert report.total == 0
        assert report.payloads == []
        assert report.encode_available is False
        assert report.lhost == "127.0.0.1"
        assert report.lport == 4444

    def test_payload_report_with_items(self):
        p = Payload(type="bash", command="cmd", listener_command="nc")
        report = PayloadReport(target="test.com", payloads=[p], encode_available=True)
        assert len(report.payloads) == 1
        assert report.encode_available is True
        assert report.lhost == "127.0.0.1"

    def test_payload_report_by_type(self):
        p1 = Payload(type="bash", command="b", listener_command="nc")
        p2 = Payload(type="python", command="p", listener_command="nc")
        report = PayloadReport(target="t", payloads=[p1, p2])
        assert len(report.by_type("bash")) == 1
        assert len(report.by_type("python")) == 1
        assert len(report.by_type("nonexistent")) == 0


# ── Base payload generation tests ───────────────────────────────────────────


LHOST = "10.0.0.1"
LPORT = 5555


class TestGenerateBashReverseShell:
    def test_basic(self):
        p = generate_bash_reverse_shell(LHOST, LPORT)
        assert p.type == "bash"
        assert LHOST in p.command
        assert str(LPORT) in p.command
        assert "/dev/tcp" in p.command
        assert "nc -lvnp" in p.listener_command

    def test_encoded(self):
        p = generate_bash_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded is True
        assert p.encoded_command is not None
        assert "base64" in p.encoded_command
        assert p.command != p.encoded_command

    def test_description(self):
        p = generate_bash_reverse_shell(LHOST, LPORT)
        assert "Bash reverse shell" in p.description


class TestGeneratePythonReverseShell:
    def test_basic(self):
        p = generate_python_reverse_shell(LHOST, LPORT)
        assert p.type == "python"
        assert LHOST in p.command
        assert str(LPORT) in p.command
        assert "socket" in p.command
        assert "rlwrap" in p.listener_command

    def test_encoded(self):
        p = generate_python_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded is True
        assert "base64" in p.encoded_command

    def test_commands_different_when_encoded(self):
        normal = generate_python_reverse_shell(LHOST, LPORT)
        encoded = generate_python_reverse_shell(LHOST, LPORT, encode=True)
        assert normal.command != encoded.encoded_command


class TestGeneratePython3ReverseShell:
    def test_basic(self):
        p = generate_python3_reverse_shell(LHOST, LPORT)
        assert p.type == "python"
        assert LHOST in p.command
        assert "socket" in p.command
        assert "Python3 short" in p.description

    def test_encoded(self):
        p = generate_python3_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded is True

    def test_shorter_than_standard(self):
        standard = generate_python_reverse_shell(LHOST, LPORT)
        short = generate_python3_reverse_shell(LHOST, LPORT)
        assert len(short.command) <= len(standard.command)


class TestGeneratePowerShellReverseShell:
    def test_basic(self):
        p = generate_powershell_reverse_shell(LHOST, LPORT)
        assert p.type == "powershell"
        assert "powershell" in p.command.lower()
        assert LHOST in p.command

    def test_encoded(self):
        p = generate_powershell_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded is True
        assert "Enc" in p.encoded_command or "encodedcommand" in p.encoded_command.lower()

    def test_utf16_encoding(self):
        p = generate_powershell_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded_command is not None


class TestGenerateNetcatReverseShell:
    def test_basic(self):
        p = generate_netcat_reverse_shell(LHOST, LPORT)
        assert p.type == "netcat"
        assert "-e /bin/sh" in p.command
        assert LHOST in p.command

    def test_encoded(self):
        p = generate_netcat_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded is True

    def nc_listener_command(self):
        p = generate_netcat_reverse_shell(LHOST, LPORT)
        assert "nc -lvnp" in p.listener_command


class TestGeneratePHPReverseShell:
    def test_basic(self):
        p = generate_php_reverse_shell(LHOST, LPORT)
        assert p.type == "php"
        assert "php -r" in p.command
        assert "fsockopen" in p.command

    def test_encoded(self):
        p = generate_php_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded is True
        assert "base64" in p.encoded_command.lower()


class TestGeneratePerlReverseShell:
    def test_basic(self):
        p = generate_perl_reverse_shell(LHOST, LPORT)
        assert p.type == "perl"
        assert "perl -e" in p.command
        assert "Socket" in p.command

    def test_encoded(self):
        p = generate_perl_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded is True
        assert "MIME::Base64" in p.encoded_command


class TestGenerateRubyReverseShell:
    def test_basic(self):
        p = generate_ruby_reverse_shell(LHOST, LPORT)
        assert p.type == "ruby"
        assert "ruby -e" in p.command
        assert "TCPSocket" in p.command

    def test_encoded(self):
        p = generate_ruby_reverse_shell(LHOST, LPORT, encode=True)
        assert p.encoded is True
        assert "Base64" in p.encoded_command


# ── Specialized payload tests ───────────────────────────────────────────────


class TestGenerateNcatSSLReverseShell:
    def test_basic(self):
        p = generate_ncat_ssl_reverse_shell(LHOST, LPORT)
        assert p.type == "netcat"
        assert "--ssl" in p.command
        assert "-e /bin/sh" in p.command
        assert "--ssl" in p.listener_command


class TestGenerateSocatReverseShell:
    def test_basic(self):
        p = generate_socat_reverse_shell(LHOST, LPORT)
        assert p.type == "socat"
        assert "socat" in p.command
        assert "EXEC:/bin/sh" in p.command
        assert "TCP-LISTEN" in p.listener_command


class TestGenerateAwkReverseShell:
    def test_basic(self):
        p = generate_awk_reverse_shell(LHOST, LPORT)
        assert p.type == "awk"
        assert "awk" in p.command
        assert "/inet/tcp" in p.command


class TestGenerateTelnetReverseShell:
    def test_basic(self):
        p = generate_telnet_reverse_shell(LHOST, LPORT)
        assert p.type == "telnet"
        assert "mknod" in p.command
        assert "telnet" in p.command
        assert "requires mknod" in p.description


# ── MSFVenom integration tests ──────────────────────────────────────────────


class TestTryMsfvenomGenerate:
    @pytest.mark.asyncio
    async def test_msfvenom_success(self):
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"binary_payload_data", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_proc)):
            p = await try_msfvenom_generate("linux_x64", LHOST, LPORT)
            assert p is not None
            assert p.type == "msfvenom"
            assert "msfvenom" in p.command
            assert "multi/handler" in p.listener_command

    @pytest.mark.asyncio
    async def test_msfvenom_not_found(self):
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            p = await try_msfvenom_generate("linux_x64", LHOST, LPORT)
            assert p is None

    @pytest.mark.asyncio
    async def test_msfvenom_timeout(self):
        mock_proc = AsyncMock()
        mock_proc.communicate.side_effect = asyncio.TimeoutError

        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_proc)):
            p = await try_msfvenom_generate("linux_x64", LHOST, LPORT)
            assert p is None

    @pytest.mark.asyncio
    async def test_msfvenom_nonzero_return(self):
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"error")
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_proc)):
            p = await try_msfvenom_generate("linux_x64", LHOST, LPORT)
            assert p is None

    @pytest.mark.asyncio
    async def test_unknown_payload_type(self):
        p = await try_msfvenom_generate("unknown_type", LHOST, LPORT)
        assert p is None

    @pytest.mark.asyncio
    async def test_msfvenom_with_encoding(self):
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"data", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_proc)):
            p = await try_msfvenom_generate("linux_x64", LHOST, LPORT, encode=True)
            assert p is not None
            assert p.encoded is True


# ── Payload dispatch tests ──────────────────────────────────────────────────


class TestGeneratePayload:
    @pytest.mark.asyncio
    async def test_bash_type(self):
        p = await generate_payload("bash", LHOST, LPORT)
        assert p is not None
        assert p.type == "bash"

    @pytest.mark.asyncio
    async def test_python_type(self):
        p = await generate_payload("python", LHOST, LPORT)
        assert p is not None
        assert p.type == "python"

    @pytest.mark.asyncio
    async def test_powershell_type(self):
        p = await generate_payload("powershell", LHOST, LPORT)
        assert p is not None
        assert p.type == "powershell"

    @pytest.mark.asyncio
    async def test_netcat_type(self):
        p = await generate_payload("netcat", LHOST, LPORT)
        assert p is not None
        assert p.type == "netcat"

    @pytest.mark.asyncio
    async def test_php_type(self):
        p = await generate_payload("php", LHOST, LPORT)
        assert p is not None
        assert p.type == "php"

    @pytest.mark.asyncio
    async def test_perl_type(self):
        p = await generate_payload("perl", LHOST, LPORT)
        assert p is not None
        assert p.type == "perl"

    @pytest.mark.asyncio
    async def test_ruby_type(self):
        p = await generate_payload("ruby", LHOST, LPORT)
        assert p is not None
        assert p.type == "ruby"

    @pytest.mark.asyncio
    async def test_socat_type(self):
        p = await generate_payload("socat", LHOST, LPORT)
        assert p is not None
        assert p.type == "socat"

    @pytest.mark.asyncio
    async def test_ncat_ssl_type(self):
        p = await generate_payload("ncat-ssl", LHOST, LPORT)
        assert p is not None
        assert p.type == "netcat"

    @pytest.mark.asyncio
    async def test_awk_type(self):
        p = await generate_payload("awk", LHOST, LPORT)
        assert p is not None
        assert p.type == "awk"

    @pytest.mark.asyncio
    async def test_telnet_type(self):
        p = await generate_payload("telnet", LHOST, LPORT)
        assert p is not None
        assert p.type == "telnet"

    @pytest.mark.asyncio
    async def test_sh_alias(self):
        """'sh' should map to bash."""
        p = await generate_payload("sh", LHOST, LPORT)
        assert p is not None
        assert p.type == "bash"

    @pytest.mark.asyncio
    async def test_ps_alias(self):
        """'ps' should map to powershell."""
        p = await generate_payload("ps", LHOST, LPORT)
        assert p is not None
        assert p.type == "powershell"

    @pytest.mark.asyncio
    async def test_nc_alias(self):
        """'nc' should map to netcat."""
        p = await generate_payload("nc", LHOST, LPORT)
        assert p is not None
        assert p.type == "netcat"

    @pytest.mark.asyncio
    async def test_unknown_type(self):
        p = await generate_payload("nonexistent_type", LHOST, LPORT)
        assert p is None

    @pytest.mark.asyncio
    async def test_auto_type(self):
        """'auto' is not a recognized type and should return None."""
        p = await generate_payload("auto", LHOST, LPORT)
        assert p is None

    @pytest.mark.asyncio
    async def test_msfvenom_type(self):
        with patch("reconprobe.payload_gen.try_msfvenom_generate", new=AsyncMock(return_value=None)):
            p = await generate_payload("msfvenom", LHOST, LPORT)
            assert p is None


# ── All payloads batch generation tests ─────────────────────────────────────


class TestGenerateAllPayloads:
    @pytest.mark.asyncio
    async def test_generates_all_types(self):
        report = await generate_all_payloads(LHOST, LPORT)
        types = {p.type for p in report.payloads}
        assert "bash" in types
        assert "python" in types
        assert "powershell" in types
        assert "netcat" in types
        assert "php" in types
        assert "perl" in types
        assert "ruby" in types

    @pytest.mark.asyncio
    async def test_minimum_count(self):
        report = await generate_all_payloads(LHOST, LPORT)
        assert len(report.payloads) >= 10

    @pytest.mark.asyncio
    async def test_all_have_lhost_lport(self):
        report = await generate_all_payloads(LHOST, LPORT)
        for p in report.payloads:
            assert LHOST in p.command or LHOST in (p.encoded_command or "")

    @pytest.mark.asyncio
    async def test_all_have_listener_commands(self):
        report = await generate_all_payloads(LHOST, LPORT)
        for p in report.payloads:
            assert p.listener_command is not None
            assert str(LPORT) in p.listener_command

    @pytest.mark.asyncio
    async def test_all_have_descriptions(self):
        report = await generate_all_payloads(LHOST, LPORT)
        for p in report.payloads:
            assert p.description is not None
            assert len(p.description) > 0

    @pytest.mark.asyncio
    async def test_with_encoding(self):
        report = await generate_all_payloads(LHOST, LPORT, encode=True)
        assert report.encode_available is True
        encoded_count = sum(1 for p in report.payloads if p.encoded)
        assert encoded_count >= 6  # Most payloads support encoding

    @pytest.mark.asyncio
    async def test_with_msfvenom(self):
        with patch("reconprobe.payload_gen.try_msfvenom_generate", new=AsyncMock(return_value=None)):
            report = await generate_all_payloads(LHOST, LPORT, try_msfvenom=True)
            # msfvenom might not be available, but the function should still work
            assert len(report.payloads) >= 10

    @pytest.mark.asyncio
    async def test_report_metadata(self):
        report = await generate_all_payloads(LHOST, LPORT)
        assert report.lhost == LHOST
        assert report.lport == LPORT
        assert report.target == ""
