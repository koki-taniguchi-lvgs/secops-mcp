import subprocess
import json
from typing import List, Optional, Dict, Any

def run_curl(
    url: str,
    options: Optional[List[str]] = None,
) -> str:
    """Run curl to transfer data.
    
    Args:
        url: The URL to interact with
        options: Additional curl options (e.g., ["-X", "POST", "-d", "data"])
    
    Returns:
        str: JSON string containing command results
    """
    try:
        # Defaults: -s for silent (no progress bar), -i for headers
        cmd = ["curl", "-s", "-i"]
        
        if options:
            cmd.extend(options)
            
        cmd.append(url)
            
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        
        # Save results
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/curl_latest.txt", "w") as f:
            f.write(result.stdout)
            
        return json.dumps({
            "success": result.returncode == 0,
            "url": url,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        })
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        })
