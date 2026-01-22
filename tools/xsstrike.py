import subprocess
import json
from typing import List, Optional, Dict, Any


def run_xsstrike(
    url: str,
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Run XSStrike to detect XSS vulnerabilities.
    
    Args:
        url: Target URL to scan
        options: Additional XSStrike options (e.g., ["--crawl", "--blind"])
        rate_limit: Maximum requests per second (optional)
    
    Returns:
        str: JSON string containing scan results
    """
    try:
        # Build the command
        import shutil
        xsstrike_path = shutil.which("xsstrike")
        if xsstrike_path:
            cmd = [xsstrike_path, "-u", url]
        else:
            cmd = ["python3", "/opt/XSStrike/xsstrike.py", "-u", url]
        
        if rate_limit:
            delay = 1.0 / rate_limit
            cmd.extend(["--delay", str(delay)])
            
        if options:
            cmd.extend(options)
        
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        # Save all results
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/xsstrike_latest.log", "w") as f:
            f.write(result.stdout)
        
        # Parse the output
        return json.dumps({
            "success": True,
            "url": url,
            "summary_log": result.stdout[-2000:],
            "note": "Use grep_stored_results('xsstrike', pattern) to search the full log."
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