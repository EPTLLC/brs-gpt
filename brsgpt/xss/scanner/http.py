from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode


async def send_test_request(http_client: Any, target_url: str, injection_point: Dict[str, Any], payload: str) -> Optional[Any]:
    try:
        if injection_point['method'] == 'GET':
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            query_params[injection_point['name']] = [payload]
            new_query = urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            return await http_client.get(test_url)
        else:
            form_data = {injection_point['name']: payload}
            if 'csrf_token' in injection_point.get('form_fields', {}):
                form_data['csrf_token'] = injection_point['form_fields']['csrf_token']
            return await http_client.post(injection_point.get('action', target_url), data=form_data)
    except Exception:
        return None
