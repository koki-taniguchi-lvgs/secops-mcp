import subprocess
import json
from typing import List, Optional, Dict, Any


def run_httpx(
    targets: List[str],
    options: Optional[List[str]] = None,
    input_file: Optional[str] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Run httpx to probe HTTP servers.
    
    Args:
        targets: List of target URLs or IPs
        options: Additional httpx options (e.g., ["-status-code", "-title"])
        input_file: Path to file containing URLs (optional)
        rate_limit: Maximum requests per second (optional)
    
    Returns:
        str: JSON string containing probe results
    """
    try:
        if input_file:
            # Use file input
            cmd = ["httpx", "-json", "-l", input_file]
            if rate_limit: cmd.extend(["-rl", str(rate_limit)])
            if options:
                cmd.extend(options)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
        else:
            # Use stdin for both single URLs and lists
            cmd = ["httpx", "-json"]
            if rate_limit: cmd.extend(["-rl", str(rate_limit)])
            if options:
                cmd.extend(options)
            result = subprocess.run(
                cmd,
                input="\n".join(targets),
                capture_output=True,
                text=True,
                check=True
            )
        
        # Parse the output (line-delimited JSON)
        try:
            results = []
            for line in result.stdout.splitlines():
                if line.strip():
                    results.append(json.loads(line))
            
            # Save all results
            import os
            os.makedirs("/tmp/secops_results", exist_ok=True)
            with open("/tmp/secops_results/httpx_latest.json", "w") as f:
                json.dump(results, f, indent=2)

            # Return a summary
            limit = 100
            summary = results[:limit]

            return json.dumps({
                "success": True,
                "targets": targets,
                "summary": summary,
                "total_count": len(results),
                "is_truncated": len(results) > limit,
                "note": "Use grep_stored_results('httpx', pattern) to search the full list."
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": f"Failed to parse JSON output: {str(e)}",
                "raw_output": result.stdout[:1000]
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