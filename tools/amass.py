import subprocess
import json
from typing import Optional, Dict, Any, List

def amass_wrapper(domain: str, passive: bool = True, options: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Wrapper for Amass subdomain enumeration tool.
    
    Args:
        domain (str): Target domain to enumerate
        passive (bool): Whether to perform passive enumeration only
        options (List[str]): Additional Amass options (e.g., ["-active", "-brute"])
    
    Returns:
        Dict[str, Any]: Results containing discovered subdomains and related information
    """
    try:
        # Build the command
        cmd = ["amass", "enum"]
        if passive:
            cmd.append("-passive")
        cmd.extend(["-d", domain])
        if options: cmd.extend(options)
        
        # Run the command with streaming output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        subdomains = []
        if process.stdout:
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line:
                    continue
                subdomains.append(clean_line)
                print(f"🔍 [amass] Found: {clean_line}", flush=True)

        _, stderr = process.communicate()
        return_code = process.wait()
        
        if return_code != 0:
            return {
                "success": False,
                "error": f"Command returned non-zero exit code {return_code}",
                "stderr": stderr
            }
        
        # Save all results
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/amass_latest.json", "w") as f:
            json.dump(subdomains, f)
            
        # Return a summary
        limit = 100
        summary = subdomains[:limit]
            
        return {
            "success": True,
            "subdomains_summary": summary,
            "total_count": len(subdomains),
            "is_truncated": len(subdomains) > limit,
            "note": "Use fetch_stored_results() if you need the full list."
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        } 