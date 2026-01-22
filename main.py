import json
import subprocess
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
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running a Nuclei security scan.
    
    Args:
        target: The target URL or IP to scan
        templates: List of specific template names to use (optional)
        severity: Filter by severity level (critical, high, medium, low, info)
        output_format: Output format (json, text)
        options: Additional Nuclei options
        rate_limit: Maximum requests per second (optional)
    """
    return run_nuclei(target, templates, severity, output_format, options, rate_limit)


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
def grep_stored_results(tool_name: str, pattern: str, context_lines: int = 2) -> str:
    """
    Search through a tool's stored results using a regex pattern.
    Returns matching lines plus context (default 2 lines) to avoid context window pollution.
    Matches are limited to 15,000 characters to prevent saturation.
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
            "nmap": "/tmp/secops_results/nmap_raw.xml",
            "curl": "/tmp/secops_results/curl_latest.txt",
            "nuclei": "/tmp/secops_results/nuclei_full.json"
        }
        
        # Lenient matching
        tool_name_clean = tool_name.lower().strip()
        matched_tool = None
        
        # 1. Try exact match
        if tool_name_clean in mapping:
            matched_tool = tool_name_clean
        else:
            # 2. Try partial match (is current tool name in the key, or vice versa?)
            for k in mapping:
                if k in tool_name_clean or tool_name_clean in k:
                    matched_tool = k
                    break
        
        if not matched_tool:
            return json.dumps({
                "success": False, 
                "error": f"Unknown tool '{tool_name}'. Supported tools: {', '.join(mapping.keys())}"
            })
        
        path = mapping[matched_tool]
        tool_name = matched_tool  # Use normalized name for consistency
        
        if not os.path.exists(path):
            return json.dumps({"success": False, "error": f"No stored results found for {tool_name}. Run the scan first."})
        
        # Run grep on the server side
        cmd = ["grep", "-i", "-E", "-C", str(context_lines), pattern, path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        
        output = res.stdout if res.stdout else "No matches found."
        is_truncated = False
        
        if len(output) > 15000:
            output = output[:15000] + "\n\n... [MATCHES TRUNCATED: Result too large. Refine your regex pattern.] ..."
            is_truncated = True
            
        return json.dumps({
            "success": True, 
            "matches": output,
            "tool": tool_name,
            "pattern": pattern,
            "is_truncated": is_truncated
        })
            
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
def ffuf_wrapper(
    url: str,
    wordlist: str,
    filter_code: Optional[str] = "404",
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running ffuf fuzzing.
    
    Args:
        url: Target URL with FUZZ keyword
        wordlist: Path to wordlist file
        filter_code: HTTP code to filter
        options: Additional ffuf options
        rate_limit: Maximum requests per second (optional)
    """
    return run_ffuf(url, wordlist, filter_code, options, rate_limit)


@mcp.tool()
def wfuzz_wrapper(
    url: str,
    wordlist: str,
    hide_code: Optional[str] = "404",
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running wfuzz fuzzing.
    
    Args:
        url: Target URL with FUZZ keyword
        wordlist: Path to wordlist file
        hide_code: HTTP code to hide
        options: Additional wfuzz options
        rate_limit: Maximum requests per second (optional)
    """
    result = run_wfuzz(url, wordlist, hide_code, options, rate_limit)
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
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running SQLMap scan.
    
    Args:
        url: Target URL to scan (must include parameter)
        options: Additional sqlmap options
        rate_limit: Maximum requests per second (optional)
    """
    return run_sqlmap(url, options, rate_limit)


@mcp.tool()
def nmap_wrapper(
    target: str,
    ports: Optional[str] = None,
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running Nmap scan.
    
    Args:
        target: Target IP or hostname
        ports: Ports to scan
        options: Additional nmap options
        rate_limit: Maximum requests per second (optional)
    """
    return run_nmap(target, ports, options, rate_limit)


@mcp.tool()
def hashcat_wrapper(
    hash_file: str,
    wordlist: str,
    mode: int = 0,
    options: Optional[List[str]] = None,
) -> str:
    """Wrapper for running Hashcat password cracking."""
    return run_hashcat(hash_file, wordlist, mode, options)


@mcp.tool()
def httpx_wrapper(
    urls: List[str],
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running HTTPX scan.
    
    Args:
        urls: List of targets
        options: Additional httpx options
        rate_limit: Maximum requests per second (optional)
    """
    result = run_httpx(urls, options, rate_limit=rate_limit)
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
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running Subfinder subdomain enumeration.
    
    Args:
        domain: Target domain
        output_format: json or text
        options: Additional subfinder options
        rate_limit: Maximum requests per second (optional)
    """
    result = run_subfinder(domain, output_format, options, rate_limit)
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
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running TLSX scan.
    
    Args:
        host: Target host
        port: Target port
        options: Additional tlsx options
        rate_limit: Maximum requests per second (optional)
    """
    return run_tlsx(host, port, options, rate_limit)


@mcp.tool()
def xsstrike_wrapper(
    url: str,
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running XSStrike scan.
    
    Args:
        url: Target URL
        options: Additional xsstrike options
        rate_limit: Maximum requests per second (optional)
    """
    return run_xsstrike(url, options, rate_limit)


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
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running Amass subdomain enumeration.
    
    Args:
        domain: Target domain
        passive: Whether to use passive scan
        options: Additional amass options
        rate_limit: Maximum requests per second (optional)
    """
    result = amass_tool(domain, passive, options, rate_limit)
    return json.dumps(result, indent=2)


@mcp.tool()
def dirsearch_wrapper(
    url: str,
    extensions: Optional[List[str]] = None,
    wordlist: Optional[str] = None,
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running Dirsearch directory brute forcing.
    
    Args:
        url: Target URL
        extensions: Extensions to check
        wordlist: Wordlist path
        options: Additional dirsearch options
        rate_limit: Maximum requests per second (optional)
    """
    result = dirsearch_tool(url, extensions, wordlist, options, rate_limit)
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
    output_format: str = "json",
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None
) -> str:
    """Wrapper for running Gospider web crawling.
    
    Args:
        target: Target URL
        depth: Crawl depth
        concurrent: Number of concurrent requests
        timeout: Request timeout
        rate_limit: Maximum requests per second (optional)
    """
    result = gospider_wrapper(
        target=target,
        depth=depth,
        concurrent=concurrent,
        timeout=timeout,
        user_agent=user_agent,
        headers=headers,
        include_subs=include_subs,
        include_other_source=include_other_source,
        output_format=output_format,
        options=options,
        rate_limit=rate_limit
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
    include_subs: bool = False,
    rate_limit: Optional[int] = None
) -> str:
    """Wrapper for running Gospider web crawling with filtering capabilities.
    
    Args:
        target: Target URL
        rate_limit: Maximum requests per second (optional)
    """
    result = gospider_crawl_with_filter(
        target=target,
        extensions=extensions,
        exclude_extensions=exclude_extensions,
        filter_length=filter_length,
        depth=depth,
        concurrent=concurrent,
        timeout=timeout,
        include_subs=include_subs,
        rate_limit=rate_limit
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
    output_format: str = "json",
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None
) -> str:
    """Wrapper for running Arjun HTTP parameter discovery.
    
    Args:
        url: Target URL
        method: HTTP method
        wordlist: Wordlist path
        headers: Headers list
        data: POST data
        delay: Delay between requests
        timeout: Request timeout
        threads: Number of threads
        stable: Use stable mode
        output_format: json or text
        options: Additional arjun options
        rate_limit: Maximum requests per second (optional)
    """
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
        output_format=output_format,
        options=options,
        rate_limit=rate_limit
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def arjun_bulk_parameter_scan(
    urls: List[str],
    method: str = "GET",
    wordlist: Optional[str] = None,
    threads: int = 25,
    stable: bool = False,
    rate_limit: Optional[int] = None
) -> str:
    """Wrapper for running Arjun parameter discovery on multiple URLs.
    
    Args:
        urls: List of target URLs
        rate_limit: Maximum requests per second (optional)
    """
    result = arjun_bulk_scan(
        urls=urls,
        method=method,
        wordlist=wordlist,
        threads=threads,
        stable=stable,
        rate_limit=rate_limit
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
    stable: bool = False,
    rate_limit: Optional[int] = None
) -> str:
    """Wrapper for running Arjun with custom parameter testing.
    
    Args:
        url: Target URL
        rate_limit: Maximum requests per second (optional)
    """
    result = arjun_with_custom_payloads(
        url=url,
        method=method,
        custom_params=custom_params,
        wordlist=wordlist,
        timeout=timeout,
        threads=threads,
        stable=stable,
        rate_limit=rate_limit
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def curl_tool(
    url: str,
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Wrapper for running curl commands to transfer data.
    
    Args:
        url: The URL to interact with
        options: Additional curl options
        rate_limit: Maximum requests per second (optional)
    """
    return run_curl(url, options, rate_limit)


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