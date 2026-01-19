import subprocess
import json
from typing import List, Optional, Dict, Any


def run_sqlmap(
    url: str,
    options: Optional[List[str]] = None,
) -> str:
    """
    Run sqlmap to test for SQL injection vulnerabilities.

    Args:
        url: Target URL to scan (should include a parameter, e.g., 'http://testphp.vulnweb.com/listproducts.php?cat=1')
        options: Additional sqlmap options (e.g., ["--dbs", "--batch"])

    Returns:
        str: JSON string containing scan results
    """
    try:
        # Check if URL contains a parameter
        if '?' not in url or '=' not in url:
            return json.dumps({
                "success": False,
                "error": "URL must include a parameter (e.g., '?id=1').",
                "usage": "Example: http://testphp.vulnweb.com/listproducts.php?cat=1"
            })

        # Build the command
        cmd = ["sqlmap", "-u", url, "--batch", "--output-dir=/tmp/sqlmap"]
        if options:
            cmd.extend(options)

        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        # Save the full output to a file
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/sqlmap_latest.log", "w") as f:
            f.write(result.stdout)

        # Parse the output for a summary
        # Look for "vulnerable" or "Payload:" in the last 5000 chars
        summary_log = result.stdout[-2000:]
        if "is vulnerable" in result.stdout:
            # Try to find the vulnerability details
            vuln_start = result.stdout.find("is vulnerable")
            summary_log = result.stdout[vuln_start-100:vuln_start+1000]

        return json.dumps({
            "success": True,
            "url": url,
            "is_vulnerable": "is vulnerable" in result.stdout,
            "summary_log": summary_log,
            "note": "Use fetch_sqlmap_output() to see the full log including HTTP traffic."
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