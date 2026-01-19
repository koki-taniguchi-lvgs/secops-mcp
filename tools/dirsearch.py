import subprocess
import json
from typing import Optional, List, Dict, Any

def dirsearch_wrapper(url: str, extensions: Optional[List[str]] = None, wordlist: Optional[str] = None) -> Dict[str, Any]:
    """
    Wrapper for Dirsearch directory and file brute forcer.
    
    Args:
        url (str): Target URL to scan
        extensions (List[str], optional): File extensions to check
        wordlist (str, optional): Path to custom wordlist
    
    Returns:
        Dict[str, Any]: Results containing discovered paths and their status codes
    """
    try:
        # Build the command
        cmd = ["dirsearch", "-u", url]
        if extensions:
            cmd.extend(["-e", ",".join(extensions)])
        if wordlist:
            cmd.extend(["-w", wordlist])

        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        # Parse the output
        findings = []
        lines = result.stdout.splitlines()
        for line in lines:
            # Look for lines like: [05:59:50] 200 -    19B - /cd/recursion/admin/users/96
            if "]" in line and " - " in line:
                parts = line.split(" - ")
                if len(parts) >= 3:
                    status_part = parts[0]
                    status_code = None
                    try:
                        status_code = int(status_part.split("]")[-1].strip())
                    except ValueError:
                        continue
                    path = parts[2].strip()
                    findings.append({
                        "status": status_code,
                        "path": path
                    })
        
        # Save all findings
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/dirsearch_latest.json", "w") as f:
            json.dump(findings, f)

        # Return a summary
        limit = 100
        summary = findings[:limit]

        return json.dumps({
            "success": True,
            "results_summary": summary,
            "total": len(findings),
            "is_truncated": len(findings) > limit,
            "note": "Use fetch_dirsearch_results() for the full list."
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