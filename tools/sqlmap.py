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

        # Run the command with streaming output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        full_output = []
        if process.stdout:
            for line in process.stdout:
                full_output.append(line)
                clean_line = line.strip()
                if not clean_line:
                    continue
                
                # Print progress (sqlmap lines usually start with [HH:MM:SS])
                if "[" in clean_line and "]" in clean_line:
                    print(f"💉 [sqlmap] {clean_line}", flush=True)

        process.wait()
        return_code = process.returncode
        stdout_str = "".join(full_output)

        if return_code != 0:
            return json.dumps({
                "success": False,
                "error": f"Command returned non-zero exit code {return_code}",
                "stdout": stdout_str
            })

        # Save the full output to a file
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/sqlmap_latest.log", "w") as f:
            f.write(stdout_str)

        # Parse the output for a summary
        # Look for "vulnerable" or "Payload:" in the last 5000 chars
        summary_log = stdout_str[-2000:]
        if "is vulnerable" in stdout_str:
            # Try to find the vulnerability details
            vuln_start = stdout_str.find("is vulnerable")
            summary_log = stdout_str[vuln_start-100:vuln_start+1000]

        return json.dumps({
            "success": True,
            "url": url,
            "is_vulnerable": "is vulnerable" in stdout_str,
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