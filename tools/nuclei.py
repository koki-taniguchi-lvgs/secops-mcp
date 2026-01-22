# tools/nuclei.py
import subprocess
import json
from typing import List, Optional, Dict, Any


def run_nuclei(
    target: str,
    templates: Optional[List[str]] = None,
    severity: Optional[str] = None,
    output_format: str = "json",
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Run a Nuclei security scan on the specified target.
    
    Args:
        target: The target URL or IP to scan
        templates: List of specific template names to use (optional)
        severity: Filter by severity level (critical, high, medium, low, info)
        output_format: Output format (json, text)
        options: Additional Nuclei options (e.g., ["-vv"])
        rate_limit: Maximum requests per second (optional)
    
    Returns:
        str: JSON string containing scan results
    """
    try:
        # Build the command
        cmd = ["nuclei", "-u", target, "-j", "-stats", "-stats-interval", "30", "-sj"]
        if templates: cmd.extend(["-t", ",".join(templates)])
        if severity: cmd.extend(["-s", severity])
        if rate_limit: cmd.extend(["-rl", str(rate_limit)])
        if options: cmd.extend(options)
        
        findings = []
        full_findings = []
        warnings = []

        # 1. Use Popen to merge stdout and stderr
        # This allows us to see stats (stderr) and findings (stdout) in one stream
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, 
            text=True,
            bufsize=1
        )

        # 2. THE STREAMING LOOP
        # This replaces result.stdout.split('\n')
        # This keeps the Cloud Run connection alive by printing every 30s
        if process.stdout:
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line:
                    continue
                
                if clean_line.startswith('{'):
                    try:
                        data = json.loads(clean_line)
                        # Check if this JSON is a "Finding" or a "Stat"
                        if "template-id" in data:
                            # Add an index for the agent to reference later
                            finding_idx = len(full_findings)
                            full_findings.append(data)

                            # Trim finding to avoid context overflow for the initial summary
                            trimmed = {
                                "finding_id": finding_idx,
                                "template-id": data.get("template-id"),
                                "info": {
                                    "name": data.get("info", {}).get("name"),
                                    "severity": data.get("info", {}).get("severity"),
                                },
                                "type": data.get("type"),
                                "matched-at": data.get("matched-at"),
                            }
                            # Remove None values
                            trimmed = {k: v for k, v in trimmed.items() if v is not None}

                            # Limit total findings returned to LLM to avoid 400 INVALID_ARGUMENT
                            if len(findings) < 100:
                                findings.append(trimmed)
                                print(f"🎯 Match: {trimmed.get('info', {}).get('name')}", flush=True)
                            elif len(findings) == 100:
                                findings.append({"info": "SUMMARY: Additional findings omitted from this summary. Use get_nuclei_details() to see all or specific findings."})
                                print(f"⚠️ Limit reached (100 matches in summary), continuing collection in background", flush=True)
                        elif "frames" in data or "requests" in data:
                            # Use .get() with defaults so it doesn't crash if a key is missing
                            reqs = data.get('requests', 0)
                            rps = data.get('rps', 0)
                            matched = data.get('matched', 0)
                            
                            # Print a more informative heartbeat
                            print(f"📊 [HEARTBEAT] Reqs: {reqs} | RPS: {rps} | Matches: {matched}", flush=True)
                    except:
                        continue
                else:
                    # This catches the verbose text noise
                    warnings.append(clean_line)
        # 3. Finalize
        return_code = process.wait()
        
        if return_code != 0:
            # Recreate your CalledProcessError logic manually
            return json.dumps({
                "success": False,
                "error": f"Command returned non-zero exit code {return_code}",
                "stderr": "\n".join(warnings) if warnings else "No stderr captured"
            })

        # Save full findings to a temporary file for deep inspection
        try:
            import os
            os.makedirs("/tmp/secops_results", exist_ok=True)
            with open("/tmp/secops_results/nuclei_full.json", "w") as f:
                json.dump(full_findings, f)
        except Exception as e:
            print(f"Error saving full findings: {e}")

        # Return exactly what your original logic intended
        return json.dumps({
            "success": True,
            "target": target,
            "findings_count": len(full_findings),
            "summary_count": len(findings),
            "findings": findings,
            "warnings": warnings if warnings else None,
            "note": "Use fetch_nuclei_finding_detail(finding_id) to see full request/response for any finding."
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        })