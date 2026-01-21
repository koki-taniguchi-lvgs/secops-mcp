import subprocess
import json
from typing import Optional, Dict, Any, List


def gospider_wrapper(
    target: str,
    depth: int = 3,
    concurrent: int = 10,
    timeout: int = 10,
    user_agent: Optional[str] = None,
    headers: Optional[List[str]] = None,
    include_subs: bool = False,
    include_other_source: bool = False,
    output_format: str = "json",
    options: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Wrapper for Gospider web crawling tool.

    Args:
        target (str): Target URL or domain to crawl
        depth (int): Maximum crawling depth (default: 3)
        concurrent (int): Number of concurrent requests (default: 10)
        timeout (int): Request timeout in seconds (default: 10)
        user_agent (str): Custom User-Agent string
        headers (List[str]): Custom headers to include
        include_subs (bool): Include subdomains in crawling
        include_other_source (bool): Include other sources like robots.txt, sitemap.xml
        output_format (str): Output format (json, txt)
        options (List[str]): Additional Gospider options (e.g., ["--blacklist", ".*\.js"])

    Returns:
        Dict[str, Any]: Results containing discovered URLs and related information
    """
    try:
        # Validate that target includes http:// or https://
        if not target.startswith("http://") and not target.startswith("https://"):
            return {
                "success": False,
                "error": "Target URL must include http:// or https:// scheme"
            }

        # Build the command
        cmd = ["gospider", "-s", target]
        
        # Add options
        cmd.extend(["-d", str(depth)])
        cmd.extend(["-c", str(concurrent)])
        cmd.extend(["-t", str(timeout)])
        
        if user_agent:
            cmd.extend(["-u", user_agent])
            
        if headers:
            for header in headers:
                cmd.extend(["-H", header])
                
        if include_subs:
            cmd.append("--subs")
            
        if include_other_source:
            cmd.append("--other-source")
            
        if output_format == "json":
            cmd.append("--json")

        if options:
            cmd.extend(options)
        
        # Run the command with streaming output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Parse the output
        urls = []
        forms = []
        secrets = []
        other = []
        
        if process.stdout:
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line:
                    continue
                
                if output_format == "json":
                    try:
                        data = json.loads(clean_line)
                        if data.get("type") == "url":
                            url_info = {
                                "url": data.get("output"),
                                "source": data.get("source"),
                                "tag": data.get("tag"),
                                "status": data.get("status_code")
                            }
                            urls.append(url_info)
                            print(f"🕸️ [gospider] URL Found: {url_info['url']} ({url_info.get('status')})", flush=True)
                        elif data.get("type") == "form":
                            form_info = {
                                "url": data.get("output"),
                                "source": data.get("source"),
                                "tag": data.get("tag")
                            }
                            forms.append(form_info)
                            print(f"📝 [gospider] Form Found: {form_info['url']}", flush=True)
                        elif data.get("type") == "secret":
                            secret_info = {
                                "secret": data.get("output"),
                                "source": data.get("source"),
                                "tag": data.get("tag")
                            }
                            secrets.append(secret_info)
                            print(f"🔑 [gospider] Secret Found: {secret_info['tag']}", flush=True)
                        else:
                            other.append(data)
                    except json.JSONDecodeError:
                        continue
                else:
                    # Text format: [url] - http://...
                    if " - " in clean_line:
                        print(f"🕸️ [gospider] {clean_line}", flush=True)
                    other.append(clean_line)

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
        all_results = {
            "urls": urls,
            "forms": forms,
            "secrets": secrets,
            "other": other
        }
        with open("/tmp/secops_results/gospider_latest.json", "w") as f:
            json.dump(all_results, f)

        # Return a summary
        limit = 50
        return {
            "success": True,
            "target": target,
            "summary": {
                "urls": urls[:limit],
                "forms": forms[:limit],
                "secrets": secrets[:limit]
            },
            "stats": {
                "total_urls": len(urls),
                "total_forms": len(forms),
                "total_secrets": len(secrets)
            },
            "is_truncated": len(urls) > limit or len(forms) > limit or len(secrets) > limit,
            "note": "Use fetch_gospider_results() for the full list."
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def gospider_crawl_with_filter(
    target: str,
    extensions: Optional[List[str]] = None,
    exclude_extensions: Optional[List[str]] = None,
    filter_length: Optional[int] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Enhanced Gospider wrapper with filtering capabilities.
    
    Args:
        target (str): Target URL or domain to crawl
        extensions (List[str]): Only crawl URLs with these extensions
        exclude_extensions (List[str]): Exclude URLs with these extensions
        filter_length (int): Filter URLs by response length
        **kwargs: Additional arguments passed to gospider_wrapper
        
    Returns:
        Dict[str, Any]: Filtered crawling results
    """
    # Get base results
    results = gospider_wrapper(target, **kwargs)
    
    if not results["success"]:
        return results
    
    # Apply filters
    filtered_urls = results["urls"]
    
    if extensions:
        filtered_urls = [
            url for url in filtered_urls 
            if any(url["url"].endswith(f".{ext}") for ext in extensions)
        ]
    
    if exclude_extensions:
        filtered_urls = [
            url for url in filtered_urls 
            if not any(url["url"].endswith(f".{ext}") for ext in exclude_extensions)
        ]
    
    # Update results with filtered data
    results["urls"] = filtered_urls
    results["stats"]["total_urls"] = len(filtered_urls)
    results["filtered"] = True
    
    return results
