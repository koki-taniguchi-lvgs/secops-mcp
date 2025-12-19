# tools/nuclei.py
import subprocess
import json
from typing import List, Optional, Dict, Any


def run_nuclei(
    target: str,
    templates: Optional[List[str]] = None,
    severity: Optional[str] = None,
    output_format: str = "json",
) -> str:
    """Run a Nuclei security scan on the specified target.
    
    Args:
        target: The target URL or IP to scan
        templates: List of specific template names to use (optional)
        severity: Filter by severity level (critical, high, medium, low, info)
        output_format: Output format (json, text)
    
    Returns:
        str: JSON string containing scan results
    """
    try:
        # Build the command
        cmd = ["nuclei", "-u", target, "-j"]
        
        # Add template filters if specified
        if templates:
            cmd.extend(["-t", ",".join(templates)])
        
        # Add severity filter if specified
        if severity:
            cmd.extend(["-s", severity])
        
        # Run the scan
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse the output - Nuclei outputs JSONL (one JSON per line)
        # Filter out warning messages and other non-JSON lines
        findings = []
        warnings = []
        
        if result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                # Only parse lines that start with { (valid JSON objects)
                if line.startswith('{'):
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Skip lines that look like JSON but aren't valid
                        continue
                else:
                    # Collect warning/info messages
                    warnings.append(line)
        
        return json.dumps({
            "success": True,
            "target": target,
            "findings_count": len(findings),
            "findings": findings,
            "warnings": warnings if warnings else None
        }, indent=2)
        
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