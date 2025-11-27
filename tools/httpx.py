import subprocess
import json
from typing import List, Optional, Dict, Any


def run_httpx(
    targets: List[str],
    options: Optional[List[str]] = None,
    input_file: Optional[str] = None,
) -> str:
    """Run httpx to probe HTTP servers.
    
    Args:
        targets: List of target URLs or IPs
        options: Additional httpx options (e.g., ["-status-code", "-title"])
        input_file: Path to file containing URLs (optional)
    
    Returns:
        str: JSON string containing probe results
    """
    try:
        if input_file:
            # Use file input
            cmd = ["httpx", "-json", "-l", input_file]
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
            if options:
                cmd.extend(options)
            result = subprocess.run(
                cmd,
                input="\n".join(targets),
                capture_output=True,
                text=True,
                check=True
            )
        
        # Parse the output
        try:
            data = json.loads(result.stdout)
            return json.dumps({
                "success": True,
                "targets": targets,
                "results": data
            })
        except json.JSONDecodeError:
            return json.dumps({
                "success": False,
                "error": "Failed to parse JSON output",
                "raw_output": result.stdout
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