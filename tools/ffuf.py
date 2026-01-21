import subprocess
import json
from typing import Optional, Dict, Any, List


def run_ffuf(
    url: str,
    wordlist: str,
    filter_code: Optional[str] = "404",
    options: Optional[List[str]] = None,
) -> str:
    """Run ffuf to fuzz web application endpoints.
    
    Args:
        url: Target URL with FUZZ keyword (e.g., "http://example.com/FUZZ")
        wordlist: Path to wordlist file
        filter_code: HTTP status code to filter out (e.g., "404")
        options: Additional ffuf options (e.g., ["-recursion", "-v"])
    
    Returns:
        Dict[str, Any]: Dictionary containing fuzzing results
    """
    try:
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmpfile:
            output_path = tmpfile.name
        cmd = ["ffuf", "-w", wordlist, "-u", url, "-of", "json", "-o", output_path]
        if options: cmd.extend(options)
        
        # Run the command with streaming output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        if process.stdout:
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line:
                    continue
                # ffuf prints progress like [Status: 200, Size: 19, Words: 2, Lines: 2]
                if "[Status:" in clean_line:
                    print(f"🚀 [ffuf] Found: {clean_line}", flush=True)
                elif "Progress:" in clean_line:
                    print(f"📊 [ffuf] {clean_line}", flush=True)

        process.wait()

        try:
            with open(output_path, "r") as f:
                data = json.load(f)
            os.remove(output_path)
            findings = []
            for entry in data.get("results", []):
                findings.append({
                    "status": entry.get("status"),
                    "path": entry.get("input", {}).get("FUZZ"),
                    "url": entry.get("url"),
                    "length": entry.get("length"),
                    "words": entry.get("words"),
                    "lines": entry.get("lines")
                })
            # Save all results
            import os
            os.makedirs("/tmp/secops_results", exist_ok=True)
            with open("/tmp/secops_results/ffuf_latest.json", "w") as f:
                json.dump(data.get("results", []), f)

            # Return a summary
            limit = 100
            summary = findings[:limit]

            return json.dumps({
                "success": True,
                "url": url,
                "summary": summary,
                "total": len(findings),
                "is_truncated": len(findings) > limit,
                "note": "Use fetch_stored_results('ffuf') for the full list."
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": f"Failed to parse ffuf JSON output: {str(e)}",
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