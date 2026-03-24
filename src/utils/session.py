"""
Session management with FlareSolverr fallback.
"""

import requests
import time
from typing import Any
from .logger import get_logger

logger = get_logger(__name__)

class SessionManager:
    """Manages requests session with FlareSolverr fallback for Cloudflare."""
    
    def __init__(self):
        self.session = requests.Session()
        # Set default headers
        self.session.headers.update({
            "Referer": "https://comix.to/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"
        })
        from .config import ConfigManager
        self._config = ConfigManager()
        self.flaresolverr_url = self._config.get("flaresolverr_url", "http://localhost:8191/v1")
        self._flaresolverr_triggered = False

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        """Execute a GET request, falling back to FlareSolverr if blocked."""
        response = self.session.get(url, **kwargs)
        
        # If we get a 403, and haven't triggered FlareSolverr recently (or within this request cycle)
        is_cloudflare = "cloudflare" in response.headers.get("Server", "").lower()
        if response.status_code in [403, 503] and (is_cloudflare or "Checking your browser" in response.text or "Just a moment" in response.text):
            logger.warning(f"Cloudflare block detected for {url}. Attempting FlareSolverr bypass...")
            if self._solve_cloudflare(url):
                # Retry request
                logger.debug(f"Retrying request to {url} after FlareSolverr bypass.")
                response = self.session.get(url, **kwargs)
            else:
                logger.error("FlareSolverr bypass failed.")
                
        return response

    def _solve_cloudflare(self, target_url: str) -> bool:
        """Use FlareSolverr to get clearance cookies."""
        try:
            # Create session
            logger.debug(f"Creating FlareSolverr session at {self.flaresolverr_url}...")
            session_res = requests.post(self.flaresolverr_url, json={
                "cmd": "sessions.create"
            }, timeout=30).json()
            
            if session_res.get("status") != "ok":
                logger.error(f"Failed to create FlareSolverr session: {session_res}")
                return False
                
            session_id = session_res.get("session")
            
            # Request URL via FlareSolverr
            logger.debug(f"Requesting {target_url} via FlareSolverr...")
            req_res = requests.post(self.flaresolverr_url, json={
                "cmd": "request.get",
                "url": target_url,
                "session": session_id,
                "maxTimeout": 60000
            }, timeout=65).json()
            
            if req_res.get("status") == "ok":
                solution = req_res.get("solution", {})
                
                # Update cookies
                cookies = solution.get("cookies", [])
                for cookie in cookies:
                    self.session.cookies.set(cookie["name"], cookie["value"], domain=cookie.get("domain", ""))
                    
                # Update user agent
                user_agent = solution.get("userAgent")
                if user_agent:
                    self.session.headers.update({"User-Agent": user_agent})
                    
                logger.info(f"Successfully bypassed Cloudflare. Got {len(cookies)} cookies.")
                success = True
            else:
                logger.error(f"FlareSolverr request failed: {req_res}")
                success = False
                
            # Destroy session
            requests.post(self.flaresolverr_url, json={
                "cmd": "sessions.destroy",
                "session": session_id
            }, timeout=10)
            
            return success
            
        except Exception as e:
            logger.error(f"Error during FlareSolverr bypass: {e}")
            return False

# Singleton instance
_session_manager = None

def get_session() -> SessionManager:
    """Get the singleton session manager."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
