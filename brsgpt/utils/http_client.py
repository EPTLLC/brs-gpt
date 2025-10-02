# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 19:05:41 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

"""
HTTP Client with Rate Limiting and Security Features

Professional HTTP client for cybersecurity analysis with:
- Intelligent rate limiting and backoff
- Security-focused headers and user agents
- Async/await support for performance
- Error handling and retry logic
"""

import asyncio
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin
import ssl

import aiohttp
from asyncio_throttle import Throttler


class HttpClient:
    """Professional HTTP client for cybersecurity analysis."""
    
    def __init__(self, rate_limit: float = 8.0, timeout: int = 15, max_retries: int = 3, cache_ttl: int = 30):
        """
        Initialize HTTP client with security-focused defaults.
        
        Args:
            rate_limit: Requests per second limit
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_retries = max_retries
        self.throttler = Throttler(rate_limit=rate_limit)
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Any] = {}
        
        # Security-focused headers
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # SSL context for security testing
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    async def get(self, url: str, headers: Optional[Dict[str, str]] = None, 
                  params: Optional[Dict[str, Any]] = None) -> Optional[aiohttp.ClientResponse]:
        """
        Perform GET request with rate limiting and retries.
        
        Args:
            url: Target URL
            headers: Additional headers
            params: URL parameters
            
        Returns:
            Response object or None if failed
        """
        # Try cache first
        cache_key = self._make_cache_key('GET', url, params)
        cached = self._get_cached_response(cache_key)
        if cached:
            return cached
        resp = await self._request('GET', url, headers=headers, params=params)
        if resp:
            # Read content for caching
            try:
                body = await resp.read()
                self._store_cached_response(cache_key, resp.status, dict(resp.headers), body)
            except Exception:
                pass
        return resp
    
    async def post(self, url: str, data: Optional[Dict[str, Any]] = None,
                   headers: Optional[Dict[str, str]] = None) -> Optional[aiohttp.ClientResponse]:
        """
        Perform POST request with rate limiting and retries.
        
        Args:
            url: Target URL
            data: POST data
            headers: Additional headers
            
        Returns:
            Response object or None if failed
        """
        return await self._request('POST', url, data=data, headers=headers)
    
    async def _request(self, method: str, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """
        Internal request method with throttling and retry logic.
        
        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional request parameters
            
        Returns:
            Response object or None if failed
        """
        # Prepare headers
        headers = self.default_headers.copy()
        if kwargs.get('headers'):
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        # Apply rate limiting
        async with self.throttler:
            for attempt in range(self.max_retries):
                try:
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=100)
                    
                    async with aiohttp.ClientSession(
                        timeout=timeout,
                        connector=connector
                    ) as session:
                        async with session.request(method, url, **kwargs) as response:
                            # Read response body to ensure complete response
                            await response.read()
                            return response
                            
                except asyncio.TimeoutError:
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    return None
                    
                except aiohttp.ClientError:
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    return None
                    
                except Exception:
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    return None
        
        return None

    # --- Simple in-memory response cache for GET ---
    def _make_cache_key(self, method: str, url: str, params: Optional[Dict[str, Any]]) -> str:
        base = f"{method}:{url}"
        if params:
            try:
                items = sorted((k, str(v)) for k, v in params.items())
                base += "?" + "&".join([f"{k}={v}" for k, v in items])
            except Exception:
                pass
        return base

    def _get_cached_response(self, key: str) -> Optional[aiohttp.ClientResponse]:
        entry = self._cache.get(key)
        if not entry:
            return None
        ts, status, headers, body = entry
        if time.time() - ts > self.cache_ttl:
            self._cache.pop(key, None)
            return None
        return _CachedResponse(status, headers, body)

    def _store_cached_response(self, key: str, status: int, headers: Dict[str, str], body: bytes) -> None:
        try:
            self._cache[key] = (time.time(), status, headers, body)
        except Exception:
            pass

    async def batch_get(self, urls: List[str], 
                       headers: Optional[Dict[str, str]] = None) -> List[Optional[aiohttp.ClientResponse]]:
        """
        Perform batch GET requests with concurrency control.
        
        Args:
            urls: List of URLs to request
            headers: Additional headers
            
        Returns:
            List of response objects (None for failed requests)
        """
        semaphore = asyncio.Semaphore(32)  # Limit concurrent requests
        
        async def bounded_get(url: str) -> Optional[aiohttp.ClientResponse]:
            async with semaphore:
                return await self.get(url, headers=headers)
        
        tasks = [bounded_get(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def is_valid_url(self, url: str) -> bool:
        """
        Validate URL format and scheme.
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            parsed = urlparse(url)
            return parsed.scheme in ('http', 'https') and parsed.netloc
        except Exception:
            return False
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize URL for consistent processing.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
    
    async def check_connectivity(self, url: str) -> bool:
        """
        Check if target is reachable.
        
        Args:
            url: Target URL
            
        Returns:
            True if reachable, False otherwise
        """
        try:
            response = await self.get(url)
            return response is not None and response.status < 500
        except Exception:
            return False


class _CachedResponse:
    """Lightweight aiohttp-like response for cached GETs."""
    def __init__(self, status: int, headers: Dict[str, str], body: bytes):
        self.status = status
        self.headers = headers
        self._body = body

    async def read(self) -> bytes:
        return self._body

    async def text(self) -> str:
        try:
            return self._body.decode('utf-8', errors='ignore')
        except Exception:
            return ''

    async def json(self) -> Any:
        import json as _json
        try:
            return _json.loads(await self.text())
        except Exception:
            return {}

