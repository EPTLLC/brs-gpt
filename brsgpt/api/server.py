# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
REST API Server for BRS-GPT

Provides HTTP API endpoints for security scanning and analysis.
"""

import asyncio
import json
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

try:
    from aiohttp import web
except ImportError:
    web = None  # type: ignore

from ..core.simple_ai_analyzer import SimpleAIAnalyzer
from ..core.intelligent_orchestrator import IntelligentOrchestrator
from ..utils.config_manager import ConfigManager
from ..version import VERSION


class BRSGPTAPIServer:
    """REST API server for BRS-GPT."""

    def __init__(self, api_key: Optional[str] = None, openai_api_key: Optional[str] = None):
        """
        Initialize API server.
        
        Args:
            api_key: API key for authentication
            openai_api_key: OpenAI API key for scanning
        """
        if web is None:
            raise RuntimeError("aiohttp is required for API server. Install with: pip install aiohttp")
        
        self.api_key = api_key or "changeme"
        self.config_manager = ConfigManager()
        self.openai_api_key = openai_api_key or self.config_manager.get_api_key()
        
        if not self.openai_api_key:
            raise ValueError("OpenAI API key is required for API server")
        
        # Active scans tracking
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.scan_results: Dict[str, Dict[str, Any]] = {}
        
        # Create app
        self.app = web.Application()
        self._setup_routes()
        self._setup_middleware()

    def _setup_middleware(self) -> None:
        """Setup middleware for authentication and CORS."""
        
        @web.middleware
        async def auth_middleware(request: web.Request, handler: Any) -> web.Response:
            """Authenticate requests."""
            # Skip auth for health and version endpoints
            if request.path in ['/health', '/version', '/']:
                return await handler(request)
            
            # Check API key
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return web.json_response({'error': 'Missing or invalid authorization'}, status=401)
            
            token = auth_header[7:]  # Remove 'Bearer '
            if token != self.api_key:
                return web.json_response({'error': 'Invalid API key'}, status=403)
            
            return await handler(request)
        
        @web.middleware
        async def cors_middleware(request: web.Request, handler: Any) -> web.Response:
            """Handle CORS."""
            if request.method == 'OPTIONS':
                return web.Response(
                    headers={
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
                        'Access-Control-Allow-Headers': 'Authorization, Content-Type',
                    }
                )
            
            response = await handler(request)
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response
        
        self.app.middlewares.append(cors_middleware)
        self.app.middlewares.append(auth_middleware)

    def _setup_routes(self) -> None:
        """Setup API routes."""
        self.app.router.add_get('/', self.index)
        self.app.router.add_get('/health', self.health)
        self.app.router.add_get('/version', self.version)
        
        # Scan endpoints
        self.app.router.add_post('/api/v1/scan', self.create_scan)
        self.app.router.add_post('/api/v1/scan/smart', self.create_smart_scan)
        self.app.router.add_get('/api/v1/scan/{scan_id}', self.get_scan_status)
        self.app.router.add_get('/api/v1/scan/{scan_id}/results', self.get_scan_results)
        self.app.router.add_delete('/api/v1/scan/{scan_id}', self.cancel_scan)
        self.app.router.add_get('/api/v1/scans', self.list_scans)

    async def index(self, request: web.Request) -> web.Response:
        """API index endpoint."""
        return web.json_response({
            'name': 'BRS-GPT API',
            'version': VERSION,
            'documentation': '/api/v1/docs',
            'endpoints': {
                'health': '/health',
                'version': '/version',
                'create_scan': 'POST /api/v1/scan',
                'create_smart_scan': 'POST /api/v1/scan/smart',
                'get_scan_status': 'GET /api/v1/scan/{scan_id}',
                'get_scan_results': 'GET /api/v1/scan/{scan_id}/results',
                'cancel_scan': 'DELETE /api/v1/scan/{scan_id}',
                'list_scans': 'GET /api/v1/scans'
            }
        })

    async def health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({
            'status': 'healthy',
            'version': VERSION,
            'active_scans': len(self.active_scans),
            'timestamp': datetime.utcnow().isoformat()
        })

    async def version(self, request: web.Request) -> web.Response:
        """Version endpoint."""
        return web.json_response({
            'version': VERSION,
            'api_version': 'v1',
            'company': 'EasyProTech LLC',
            'contact': 'https://t.me/easyprotech'
        })

    async def create_scan(self, request: web.Request) -> web.Response:
        """Create a new scan."""
        try:
            data = await request.json()
            target = data.get('target')
            profile = data.get('profile', 'fast')
            model = data.get('model')
            
            if not target:
                return web.json_response({'error': 'Target is required'}, status=400)
            
            if profile not in ['lightning', 'fast', 'balanced', 'deep']:
                return web.json_response({'error': 'Invalid profile'}, status=400)
            
            # Create scan ID
            scan_id = str(uuid.uuid4())
            
            # Store scan info
            self.active_scans[scan_id] = {
                'id': scan_id,
                'target': target,
                'profile': profile,
                'model': model,
                'status': 'queued',
                'created_at': datetime.utcnow().isoformat(),
                'type': 'basic'
            }
            
            # Start scan in background
            asyncio.create_task(self._execute_scan(scan_id, target, profile, model))
            
            return web.json_response({
                'scan_id': scan_id,
                'status': 'queued',
                'target': target,
                'profile': profile,
                'message': 'Scan queued successfully'
            }, status=202)
        
        except json.JSONDecodeError:
            return web.json_response({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)

    async def create_smart_scan(self, request: web.Request) -> web.Response:
        """Create a smart scan (AI Orchestrator)."""
        try:
            data = await request.json()
            target = data.get('target')
            profile = data.get('profile', 'balanced')
            model = data.get('model')
            
            if not target:
                return web.json_response({'error': 'Target is required'}, status=400)
            
            scan_id = str(uuid.uuid4())
            
            self.active_scans[scan_id] = {
                'id': scan_id,
                'target': target,
                'profile': profile,
                'model': model,
                'status': 'queued',
                'created_at': datetime.utcnow().isoformat(),
                'type': 'smart'
            }
            
            asyncio.create_task(self._execute_smart_scan(scan_id, target, profile, model))
            
            return web.json_response({
                'scan_id': scan_id,
                'status': 'queued',
                'target': target,
                'profile': profile,
                'type': 'smart',
                'message': 'Smart scan queued successfully'
            }, status=202)
        
        except json.JSONDecodeError:
            return web.json_response({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)

    async def get_scan_status(self, request: web.Request) -> web.Response:
        """Get scan status."""
        scan_id = request.match_info['scan_id']
        
        if scan_id in self.active_scans:
            return web.json_response(self.active_scans[scan_id])
        
        if scan_id in self.scan_results:
            return web.json_response({
                'id': scan_id,
                'status': 'completed',
                'completed_at': self.scan_results[scan_id].get('completed_at')
            })
        
        return web.json_response({'error': 'Scan not found'}, status=404)

    async def get_scan_results(self, request: web.Request) -> web.Response:
        """Get scan results."""
        scan_id = request.match_info['scan_id']
        
        if scan_id not in self.scan_results:
            if scan_id in self.active_scans:
                return web.json_response({'error': 'Scan not yet completed'}, status=202)
            return web.json_response({'error': 'Scan not found'}, status=404)
        
        return web.json_response(self.scan_results[scan_id])

    async def cancel_scan(self, request: web.Request) -> web.Response:
        """Cancel a scan."""
        scan_id = request.match_info['scan_id']
        
        if scan_id not in self.active_scans:
            return web.json_response({'error': 'Scan not found'}, status=404)
        
        self.active_scans[scan_id]['status'] = 'cancelled'
        
        return web.json_response({
            'scan_id': scan_id,
            'status': 'cancelled',
            'message': 'Scan cancelled successfully'
        })

    async def list_scans(self, request: web.Request) -> web.Response:
        """List all scans."""
        all_scans = []
        
        # Active scans
        for scan in self.active_scans.values():
            all_scans.append({
                'id': scan['id'],
                'target': scan['target'],
                'status': scan['status'],
                'type': scan['type'],
                'created_at': scan['created_at']
            })
        
        # Completed scans
        for scan_id, result in self.scan_results.items():
            all_scans.append({
                'id': scan_id,
                'target': result.get('target'),
                'status': 'completed',
                'type': result.get('type', 'basic'),
                'completed_at': result.get('completed_at')
            })
        
        return web.json_response({
            'scans': all_scans,
            'total': len(all_scans),
            'active': len(self.active_scans),
            'completed': len(self.scan_results)
        })

    async def _execute_scan(self, scan_id: str, target: str, profile: str, model: Optional[str]) -> None:
        """Execute a basic scan."""
        try:
            self.active_scans[scan_id]['status'] = 'running'
            self.active_scans[scan_id]['started_at'] = datetime.utcnow().isoformat()
            
            # Apply profile
            if profile:
                self.config_manager.apply_profile(profile)
            
            # Override model if specified
            if model:
                self.config_manager.update_settings({'ai': {'model': model}})
            
            # Run scan
            analyzer = SimpleAIAnalyzer(self.openai_api_key, model or 'gpt-4o')
            log_file = await analyzer.analyze_domain(target)
            
            # Read results
            results = self._read_results(log_file)
            
            # Store results
            self.scan_results[scan_id] = {
                'id': scan_id,
                'target': target,
                'type': 'basic',
                'profile': profile,
                'results': results,
                'cost': analyzer.total_cost,
                'queries': analyzer.total_queries,
                'completed_at': datetime.utcnow().isoformat()
            }
            
            # Remove from active scans
            del self.active_scans[scan_id]
        
        except Exception as e:
            self.active_scans[scan_id]['status'] = 'failed'
            self.active_scans[scan_id]['error'] = str(e)

    async def _execute_smart_scan(self, scan_id: str, target: str, profile: str, model: Optional[str]) -> None:
        """Execute a smart scan (AI Orchestrator)."""
        try:
            self.active_scans[scan_id]['status'] = 'running'
            self.active_scans[scan_id]['started_at'] = datetime.utcnow().isoformat()
            
            if profile:
                self.config_manager.apply_profile(profile)
            
            if model:
                self.config_manager.update_settings({'ai': {'model': model}})
            
            orchestrator = IntelligentOrchestrator(self.openai_api_key)
            report_path = await orchestrator.ai_analyze_target(target, None)
            
            results = self._read_results(report_path)
            
            cost_info = orchestrator.ai_state.get('cost_tracking', {})
            self.scan_results[scan_id] = {
                'id': scan_id,
                'target': target,
                'type': 'smart',
                'profile': profile,
                'results': results,
                'cost': cost_info.get('total_cost', 0.0),
                'queries': cost_info.get('queries_made', 0),
                'completed_at': datetime.utcnow().isoformat()
            }
            
            del self.active_scans[scan_id]
        
        except Exception as e:
            self.active_scans[scan_id]['status'] = 'failed'
            self.active_scans[scan_id]['error'] = str(e)

    def _read_results(self, log_file: str) -> Dict[str, Any]:
        """Read scan results from file."""
        try:
            log_path = Path(log_file)
            
            # Try to read JSON report
            json_file = log_path.with_suffix('.json')
            if json_file.exists():
                with open(json_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            # Fallback to text report
            if log_path.exists():
                with open(log_path, 'r', encoding='utf-8') as f:
                    return {'text_report': f.read()}
            
            return {'error': 'Results file not found'}
        
        except Exception as e:
            return {'error': f'Failed to read results: {str(e)}'}


# Global app instance
app = None


def start_api_server(host: str = '0.0.0.0', port: int = 8000, 
                    api_key: Optional[str] = None, openai_api_key: Optional[str] = None) -> None:
    """
    Start the API server.
    
    Args:
        host: Host to bind to
        port: Port to bind to
        api_key: API key for authentication
        openai_api_key: OpenAI API key
    """
    global app
    
    if web is None:
        raise RuntimeError("aiohttp is required for API server. Install with: pip install aiohttp")
    
    server = BRSGPTAPIServer(api_key=api_key, openai_api_key=openai_api_key)
    app = server.app
    
    print(f"Starting BRS-GPT API Server v{VERSION}")
    print(f"Listening on http://{host}:{port}")
    print(f"API Documentation: http://{host}:{port}/")
    
    web.run_app(app, host=host, port=port)


__all__ = ['BRSGPTAPIServer', 'app', 'start_api_server']

