import json
from typing import List, Optional
import signal
import threading
import logging
import sys

import os
from mcp.server.fastmcp import FastMCP

# Configure logging to show subprocess output in docker logs
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

from tools.nuclei import run_nuclei
from tools.ffuf import run_ffuf
from tools.wfuzz import run_wfuzz
from tools.sqlmap import run_sqlmap
from tools.nmap import run_nmap
from tools.hashcat import run_hashcat
from tools.httpx import run_httpx
from tools.subfinder import run_subfinder
from tools.tlsx import run_tlsx
from tools.xsstrike import run_xsstrike
from tools.ipinfo import run_ipinfo
from tools.amass import amass_wrapper as amass_tool
from tools.dirsearch import dirsearch_wrapper as dirsearch_tool
from tools.gospider import gospider_wrapper, gospider_crawl_with_filter
from tools.arjun import arjun_wrapper, arjun_bulk_scan, arjun_with_custom_payloads
from tools.curl import run_curl

# Create server
mcp = FastMCP(name="secops-mcp",
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 8081)),
    log_level="INFO"
)

# Graceful shutdown flag
graceful_shutdown = threading.Event()

def handle_shutdown_signal(signum, frame):
    """Handle shutdown signals to ensure proper cleanup."""
    print("\nReceived shutdown signal. Cleaning up resources...")
    graceful_shutdown.set()

# Register signal handlers for graceful shutdown
signal.signal(signal.SIGINT, handle_shutdown_signal)
signal.signal(signal.SIGTERM, handle_shutdown_signal)


@mcp.tool()
def nuclei_scan_wrapper(
    target: str,
    templates: Optional[List[str]] = None,
    severity: Optional[str] = None,
    output_format: str = "json",
) -> str:
    """Wrapper for running a Nuclei security scan."""
    return run_nuclei(target, templates, severity, output_format)


@mcp.tool()
def fetch_nuclei_finding_detail(finding_id: int) -> str:
    """
    Fetch the full details of a specific Nuclei finding, including request and response.
    The finding_id is the index provided in the nuclei_scan_wrapper summary.
    """
    try:
        path = "/tmp/secops_results/nuclei_full.json"
        if not os.path.exists(path):
            return json.dumps({"success": False, "error": "No nuclei scan results found. Run a scan first."})
        
        with open(path, "r") as f:
            full_findings = json.load(f)
        
        if 0 <= finding_id < len(full_findings):
            return json.dumps({
                "success": True,
                "finding": full_findings[finding_id]
            }, indent=2)
        else:
            return json.dumps({"success": False, "error": f"Finding ID {finding_id} out of range (0-{len(full_findings)-1})"})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
def fetch_stored_results(tool_name: str) -> str:
    """
    Fetch the full results of a previously run tool (subfinder, amass, gospider, dirsearch).
    Results are returned in full, so use with caution if you expect massive output.
    """
    try:
        mapping = {
            "subfinder": "/tmp/secops_results/subfinder_latest.json",
            "amass": "/tmp/secops_results/amass_latest.json",
            "gospider": "/tmp/secops_results/gospider_latest.json",
            "dirsearch": "/tmp/secops_results/dirsearch_latest.json",
            "sqlmap": "/tmp/secops_results/sqlmap_latest.log",
            "httpx": "/tmp/secops_results/httpx_latest.json",
            "ffuf": "/tmp/secops_results/ffuf_latest.json",
            "wfuzz": "/tmp/secops_results/wfuzz_latest.json",
            "xsstrike": "/tmp/secops_results/xsstrike_latest.log",
            "nmap": "/tmp/secops_results/nmap_raw.xml"
        }
        
        if tool_name not in mapping:
            return json.dumps({"success": False, "error": f"Unknown tool or no storage configured for {tool_name}"})
        
        path = mapping[tool_name]
        if not os.path.exists(path):
            return json.dumps({"success": False, "error": f"No stored results found for {tool_name}. Run the scan first."})
        
        if path.endswith(".json"):
            with open(path, "r") as f:
                data = json.load(f)
            return json.dumps({"success": True, "results": data}, indent=2)
        else:
            with open(path, "r") as f:
                data = f.read()
            return json.dumps({"success": True, "output": data})
            
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
def ffuf_wrapper(
    url: str,
    wordlist: str,
    filter_code: Optional[str] = "404",
) -> str:
    """Wrapper for running ffuf fuzzing."""
    return run_ffuf(url, wordlist, filter_code)


@mcp.tool()
def wfuzz_wrapper(
    url: str,
    wordlist: str,
    hide_code: Optional[str] = "404",
) -> str:
    """Wrapper for running wfuzz fuzzing."""
    result = run_wfuzz(url, wordlist, hide_code)
    try:
        if result:
            data = json.loads(result)
            return json.dumps({"success": True, "url": url, "results": data})
        else:
            return json.dumps({"success": False, "error": "No output from wfuzz", "raw_output": result})
    except Exception:
        return json.dumps({"success": False, "error": "Failed to parse JSON output", "raw_output": result})


@mcp.tool()
def sqlmap_wrapper(
    url: str,
    options: Optional[List[str]] = None,
) -> str:
    """Wrapper for running SQLMap scan."""
    return run_sqlmap(url, options)


@mcp.tool()
def nmap_wrapper(
    target: str,
    ports: Optional[str] = None,
    options: Optional[List[str]] = None,
) -> str:
    """Wrapper for running Nmap scan."""
    return run_nmap(target, ports, options)


@mcp.tool()
def hashcat_wrapper(
    hash_file: str,
    wordlist: str,
    mode: int = 0,
) -> str:
    """Wrapper for running Hashcat password cracking."""
    return run_hashcat(hash_file, wordlist, mode)


@mcp.tool()
def httpx_wrapper(
    urls: List[str],
    options: Optional[List[str]] = None,
) -> str:
    """Wrapper for running HTTPX scan."""
    result = run_httpx(urls, options)
    try:
        # httpx may output multiple JSON objects per line
        lines = result.splitlines()
        parsed = []
        for line in lines:
            try:
                parsed.append(json.loads(line))
            except Exception:
                continue
        return json.dumps({"success": True, "urls": urls, "results": parsed})
    except Exception:
        return json.dumps({"success": False, "error": "Failed to parse JSON output", "raw_output": result})


@mcp.tool()
def subfinder_wrapper(
    domain: str,
    output_format: Optional[str] = "json",
) -> str:
    """Wrapper for running Subfinder subdomain enumeration."""
    result = run_subfinder(domain, output_format)
    try:
        # result is already a JSON string from run_subfinder
        parsed = json.loads(result)
        return json.dumps(parsed)
    except Exception:
        return json.dumps({"success": False, "error": "Failed to parse JSON output", "raw_output": result})


@mcp.tool()
def tlsx_wrapper(
    host: str,
    port: Optional[int] = 443,
) -> str:
    """Wrapper for running TLSX scan."""
    return run_tlsx(host, port)


@mcp.tool()
def xsstrike_wrapper(
    url: str,
    options: Optional[List[str]] = None,
) -> str:
    """Wrapper for running XSStrike scan."""
    return run_xsstrike(url, options)


@mcp.tool()
def ipinfo_wrapper(
    ip: Optional[str] = None,
) -> str:
    """Wrapper for getting IP information using ipinfo.io."""
    return run_ipinfo(ip)


@mcp.tool()
def amass_scan(
    domain: str,
    passive: bool = True,
) -> str:
    """Wrapper for running Amass subdomain enumeration."""
    result = amass_tool(domain, passive)
    return json.dumps(result, indent=2)


@mcp.tool()
def dirsearch_wrapper(
    url: str,
    extensions: Optional[List[str]] = None,
    wordlist: Optional[str] = None,
) -> str:
    """Wrapper for running Dirsearch directory brute forcing."""
    result = dirsearch_tool(url, extensions, wordlist)
    return json.dumps(result, indent=2)


@mcp.tool()
def gospider_scan(
    target: str,
    depth: int = 3,
    concurrent: int = 10,
    timeout: int = 10,
    user_agent: Optional[str] = None,
    headers: Optional[List[str]] = None,
    include_subs: bool = False,
    include_other_source: bool = False,
    output_format: str = "json"
) -> str:
    """Wrapper for running Gospider web crawling."""
    result = gospider_wrapper(
        target=target,
        depth=depth,
        concurrent=concurrent,
        timeout=timeout,
        user_agent=user_agent,
        headers=headers,
        include_subs=include_subs,
        include_other_source=include_other_source,
        output_format=output_format
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def gospider_filtered_scan(
    target: str,
    extensions: Optional[List[str]] = None,
    exclude_extensions: Optional[List[str]] = None,
    filter_length: Optional[int] = None,
    depth: int = 3,
    concurrent: int = 10,
    timeout: int = 10,
    include_subs: bool = False
) -> str:
    """Wrapper for running Gospider web crawling with filtering capabilities."""
    result = gospider_crawl_with_filter(
        target=target,
        extensions=extensions,
        exclude_extensions=exclude_extensions,
        filter_length=filter_length,
        depth=depth,
        concurrent=concurrent,
        timeout=timeout,
        include_subs=include_subs
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def arjun_scan(
    url: str,
    method: str = "GET",
    wordlist: Optional[str] = None,
    headers: Optional[List[str]] = None,
    data: Optional[str] = None,
    delay: int = 0,
    timeout: int = 10,
    threads: int = 25,
    stable: bool = False,
    output_format: str = "json"
) -> str:
    """Wrapper for running Arjun HTTP parameter discovery."""
    result = arjun_wrapper(
        url=url,
        method=method,
        wordlist=wordlist,
        headers=headers,
        data=data,
        delay=delay,
        timeout=timeout,
        threads=threads,
        stable=stable,
        output_format=output_format
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def arjun_bulk_parameter_scan(
    urls: List[str],
    method: str = "GET",
    wordlist: Optional[str] = None,
    threads: int = 25,
    stable: bool = False
) -> str:
    """Wrapper for running Arjun parameter discovery on multiple URLs."""
    result = arjun_bulk_scan(
        urls=urls,
        method=method,
        wordlist=wordlist,
        threads=threads,
        stable=stable
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def arjun_custom_parameter_scan(
    url: str,
    method: str = "GET",
    custom_params: Optional[List[str]] = None,
    wordlist: Optional[str] = None,
    timeout: int = 10,
    threads: int = 25,
    stable: bool = False
) -> str:
    """Wrapper for running Arjun with custom parameter testing."""
    result = arjun_with_custom_payloads(
        url=url,
        method=method,
        custom_params=custom_params,
        wordlist=wordlist,
        timeout=timeout,
        threads=threads,
        stable=stable
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def curl_tool(
    url: str,
    options: Optional[List[str]] = None,
) -> str:
    """Wrapper for running curl commands to transfer data.
    
    Args:
        url: The URL to interact with
        options: Additional curl options (e.g., ["-X", "POST", "-d", "data"])
    """
    return run_curl(url, options)


if __name__ == "__main__":
    try:
        print("Starting MCP server...")
        mcp.run(transport="streamable-http")
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        if graceful_shutdown.is_set():
            print("Server shutting down gracefully.")
        else:
            print("Server stopped unexpectedly.")