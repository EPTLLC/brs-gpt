# BRS-GPT REST API Documentation

REST API for integrating BRS-GPT security scanner into your applications and workflows.

## Quick Start

### Start API Server

```bash
# Set API keys
export OPENAI_API_KEY=sk-your-openai-key
export API_KEY=your-api-authentication-key

# Start server
brs-gpt api --host 0.0.0.0 --port 8000
```

### Docker

```bash
docker-compose --profile api up -d brs-gpt-api
```

## Authentication

All API endpoints (except `/health` and `/version`) require Bearer token authentication:

```bash
curl -H "Authorization: Bearer your-api-key" \
  http://localhost:8000/api/v1/scans
```

## Endpoints

### Health Check

**GET** `/health`

Check API server health status.

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "0.0.1",
  "active_scans": 2,
  "timestamp": "2025-10-03T01:41:52.000000"
}
```

### Version

**GET** `/version`

Get API version information.

```bash
curl http://localhost:8000/version
```

**Response:**
```json
{
  "version": "0.0.1",
  "api_version": "v1",
  "company": "EasyProTech LLC",
  "contact": "https://t.me/easyprotech"
}
```

### Create Scan

**POST** `/api/v1/scan`

Create a new security scan.

**Request Body:**
```json
{
  "target": "example.com",
  "profile": "fast",
  "model": "gpt-4o"
}
```

**Parameters:**
- `target` (required): Target domain or URL
- `profile` (optional): Scan profile (`lightning`, `fast`, `balanced`, `deep`)
- `model` (optional): OpenAI model to use

**Example:**
```bash
curl -X POST \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","profile":"fast"}' \
  http://localhost:8000/api/v1/scan
```

**Response:**
```json
{
  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "queued",
  "target": "example.com",
  "profile": "fast",
  "message": "Scan queued successfully"
}
```

### Create Smart Scan

**POST** `/api/v1/scan/smart`

Create AI Orchestrator scan (advanced).

**Request Body:**
```json
{
  "target": "example.com",
  "profile": "balanced",
  "model": "gpt-4o"
}
```

**Example:**
```bash
curl -X POST \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","profile":"balanced"}' \
  http://localhost:8000/api/v1/scan/smart
```

### Get Scan Status

**GET** `/api/v1/scan/{scan_id}`

Get current scan status.

**Example:**
```bash
curl -H "Authorization: Bearer your-api-key" \
  http://localhost:8000/api/v1/scan/123e4567-e89b-12d3-a456-426614174000
```

**Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "target": "example.com",
  "profile": "fast",
  "status": "running",
  "created_at": "2025-10-03T01:41:52.000000",
  "started_at": "2025-10-03T01:42:00.000000",
  "type": "basic"
}
```

**Status Values:**
- `queued`: Scan is queued for execution
- `running`: Scan is currently running
- `completed`: Scan finished successfully
- `failed`: Scan failed with error
- `cancelled`: Scan was cancelled

### Get Scan Results

**GET** `/api/v1/scan/{scan_id}/results`

Get scan results (only available when status is `completed`).

**Example:**
```bash
curl -H "Authorization: Bearer your-api-key" \
  http://localhost:8000/api/v1/scan/123e4567-e89b-12d3-a456-426614174000/results
```

**Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "target": "example.com",
  "type": "basic",
  "profile": "fast",
  "results": {
    "vulnerabilities": [...],
    "ports": [...],
    "subdomains": [...]
  },
  "cost": 0.45,
  "queries": 12,
  "completed_at": "2025-10-03T01:45:00.000000"
}
```

### Cancel Scan

**DELETE** `/api/v1/scan/{scan_id}`

Cancel a running scan.

**Example:**
```bash
curl -X DELETE \
  -H "Authorization: Bearer your-api-key" \
  http://localhost:8000/api/v1/scan/123e4567-e89b-12d3-a456-426614174000
```

**Response:**
```json
{
  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "cancelled",
  "message": "Scan cancelled successfully"
}
```

### List Scans

**GET** `/api/v1/scans`

List all scans (active and completed).

**Example:**
```bash
curl -H "Authorization: Bearer your-api-key" \
  http://localhost:8000/api/v1/scans
```

**Response:**
```json
{
  "scans": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "target": "example.com",
      "status": "completed",
      "type": "basic",
      "completed_at": "2025-10-03T01:45:00.000000"
    },
    {
      "id": "223e4567-e89b-12d3-a456-426614174001",
      "target": "test.com",
      "status": "running",
      "type": "smart",
      "created_at": "2025-10-03T01:50:00.000000"
    }
  ],
  "total": 2,
  "active": 1,
  "completed": 1
}
```

## Error Responses

### 400 Bad Request

```json
{
  "error": "Target is required"
}
```

### 401 Unauthorized

```json
{
  "error": "Missing or invalid authorization"
}
```

### 403 Forbidden

```json
{
  "error": "Invalid API key"
}
```

### 404 Not Found

```json
{
  "error": "Scan not found"
}
```

### 500 Internal Server Error

```json
{
  "error": "Internal server error message"
}
```

## Client Examples

### Python

```python
import requests
import time

API_URL = "http://localhost:8000"
API_KEY = "your-api-key"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Create scan
response = requests.post(
    f"{API_URL}/api/v1/scan",
    headers=headers,
    json={"target": "example.com", "profile": "fast"}
)
scan_id = response.json()["scan_id"]
print(f"Scan ID: {scan_id}")

# Poll for completion
while True:
    status_response = requests.get(
        f"{API_URL}/api/v1/scan/{scan_id}",
        headers=headers
    )
    status = status_response.json()["status"]
    print(f"Status: {status}")
    
    if status == "completed":
        break
    elif status == "failed":
        print("Scan failed!")
        exit(1)
    
    time.sleep(5)

# Get results
results_response = requests.get(
    f"{API_URL}/api/v1/scan/{scan_id}/results",
    headers=headers
)
results = results_response.json()
print(f"Cost: ${results['cost']:.4f}")
print(f"Vulnerabilities: {len(results['results'].get('vulnerabilities', []))}")
```

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const API_URL = 'http://localhost:8000';
const API_KEY = 'your-api-key';

const headers = {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json'
};

async function scanTarget(target) {
    // Create scan
    const scanResponse = await axios.post(
        `${API_URL}/api/v1/scan`,
        { target, profile: 'fast' },
        { headers }
    );
    
    const scanId = scanResponse.data.scan_id;
    console.log(`Scan ID: ${scanId}`);
    
    // Wait for completion
    while (true) {
        const statusResponse = await axios.get(
            `${API_URL}/api/v1/scan/${scanId}`,
            { headers }
        );
        
        const status = statusResponse.data.status;
        console.log(`Status: ${status}`);
        
        if (status === 'completed') break;
        if (status === 'failed') throw new Error('Scan failed');
        
        await new Promise(resolve => setTimeout(resolve, 5000));
    }
    
    // Get results
    const resultsResponse = await axios.get(
        `${API_URL}/api/v1/scan/${scanId}/results`,
        { headers }
    );
    
    return resultsResponse.data;
}

scanTarget('example.com').then(results => {
    console.log(`Cost: $${results.cost.toFixed(4)}`);
    console.log(`Vulnerabilities: ${results.results.vulnerabilities?.length || 0}`);
});
```

### cURL

```bash
#!/bin/bash

API_URL="http://localhost:8000"
API_KEY="your-api-key"
TARGET="example.com"

# Create scan
SCAN_ID=$(curl -s -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"$TARGET\",\"profile\":\"fast\"}" \
  "$API_URL/api/v1/scan" | jq -r '.scan_id')

echo "Scan ID: $SCAN_ID"

# Wait for completion
while true; do
  STATUS=$(curl -s -H "Authorization: Bearer $API_KEY" \
    "$API_URL/api/v1/scan/$SCAN_ID" | jq -r '.status')
  echo "Status: $STATUS"
  
  if [ "$STATUS" == "completed" ]; then
    break
  elif [ "$STATUS" == "failed" ]; then
    echo "Scan failed!"
    exit 1
  fi
  
  sleep 5
done

# Get results
curl -s -H "Authorization: Bearer $API_KEY" \
  "$API_URL/api/v1/scan/$SCAN_ID/results" | jq .
```

## Rate Limiting

Currently no rate limiting is implemented. Consider implementing rate limiting in production:

- Per API key limits
- Global request limits
- Concurrent scan limits

## Security Considerations

1. Use HTTPS in production
2. Implement proper API key rotation
3. Add request validation
4. Implement rate limiting
5. Monitor for abuse
6. Log all API access
7. Use strong API keys (min 32 chars)

## Deployment

### Production Recommendations

1. Run behind reverse proxy (nginx, traefik)
2. Enable HTTPS/TLS
3. Implement authentication/authorization
4. Add monitoring and logging
5. Use process manager (systemd, supervisor)
6. Set resource limits

### Example nginx configuration

```nginx
upstream brs-gpt-api {
    server 127.0.0.1:8000;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://brs-gpt-api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

**API Version**: v1  
**BRS-GPT Version**: 0.0.1  
**Company**: EasyProTech LLC  
**Contact**: https://t.me/easyprotech

