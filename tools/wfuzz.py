import subprocess
import json
from typing import Optional, Dict, Any, List


def run_wfuzz(
    url: str,
    wordlist: str,
    show_code: Optional[str] = "200,302,403,500",
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Run wfuzz to fuzz web application endpoints.
    
    Args:
        url: Target URL with FUZZ keyword (e.g., "http://example.com/FUZZ")
        wordlist: Path to wordlist file
        show_code: HTTP status code to show (e.g., "200,302")
        options: Additional wfuzz options (e.g., ["-t", "100"])
        rate_limit: Maximum requests per second (optional)
    
    Returns:
        Dict[str, Any]: Dictionary containing fuzzing results
    """
    try:
    # Build the command
        cmd = ["wfuzz", "-w", wordlist, "--sc", show_code, "-o", "json"]
        if rate_limit:
            delay = 1.0 / rate_limit
            cmd.extend(["--delay", str(delay)])
        if options: cmd.extend(options)
        cmd.append(url)

        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        # Parse the output
        import re
        findings = []
        # Regex to match wfuzz result lines (payload, code, url)
        pattern = re.compile(r'\{"chars":.*?"code": (\d+),.*?"payload": "(.*?)",.*?"url": "(.*?)".*?\}')
        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if match:
                findings.append({
                    "status": int(match.group(1)),
                    "payload": match.group(2),
                    "url": match.group(3)
                })
        # Save all results
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/wfuzz_latest.json", "w") as f:
            json.dump(findings, f, indent=2)

        # Return a summary
        limit = 100
        summary = findings[:limit]

        return json.dumps({
            "success": True,
            "url": url,
            "summary": summary,
            "total": len(findings),
            "is_truncated": len(findings) > limit,
            "note": "Use grep_stored_results('wfuzz', pattern) to search the full list."
        })

    except subprocess.CalledProcessError as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "stderr": e.stderr
        })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        })