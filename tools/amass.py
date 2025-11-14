import subprocess
import json
from typing import Optional, Dict, Any

def amass_wrapper(domain: str, passive: bool = True) -> Dict[str, Any]:
    """
    Wrapper for Amass subdomain enumeration tool.
    
    Args:
        domain (str): Target domain to enumerate
        passive (bool): Whether to perform passive enumeration only
    
    Returns:
        Dict[str, Any]: Results containing discovered subdomains and related information
    """
    try:
        # Build the command
        cmd = ["amass", "enum"]
        if passive:
            cmd.append("-passive")
        cmd.extend(["-d", domain])
        
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse the output (plain text, each line is a subdomain)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {
            "success": True,
            "subdomains": subdomains,
            "count": len(subdomains)
        }
        
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": str(e),
            "stderr": e.stderr
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        } 