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

        # Run the command with streaming output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        findings = []
        if process.stdout:
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line:
                    continue
                
                # Look for lines like: [05:59:50] 200 -    19B - /path
                if "]" in clean_line and " - " in clean_line:
                    parts = clean_line.split(" - ")
                    if len(parts) >= 3:
                        try:
                            status_part = parts[0]
                            status_code = int(status_part.split("]")[-1].strip())
                            path = parts[2].strip()
                            finding = {
                                "status": status_code,
                                "path": path
                            }
                            findings.append(finding)
                            # Print progress for interesting status codes
                            if status_code < 400:
                                print(f"🎯 [dirsearch] Found ({status_code}): {path}", flush=True)
                            else:
                                # For 403 etc, just a heartbeat every now and then or all?
                                # Let's print all for now since dirsearch can be slow
                                print(f"🔍 [dirsearch] {status_code}: {path}", flush=True)
                        except (ValueError, IndexError):
                            continue

        _, stderr = process.communicate()
        return_code = process.wait()
        
        if return_code != 0:
            return json.dumps({
                "success": False,
                "error": f"Command returned non-zero exit code {return_code}",
                "stderr": stderr
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

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        })