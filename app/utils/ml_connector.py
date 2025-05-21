from datetime import datetime
import time
from typing import Any, Dict
import requests


class MLModelConnector:
    def __init__(self):
        self.model_endpoints = {
            'Anomaly Detection': "http://localhost:3001",
            'Malware Detection': "http://localhost:4000",
            'Phishing Detection': "http://localhost:6000",  # Added phishing model
            'Windows Log Analysis': "http://localhost:7000"
        }
        self.health_cache = {}
        self.last_checked = {}
        self.last_updates = {name: None for name in self.model_endpoints}
    
    def get_model_status(self) -> Dict[str, dict[str, Any]]:
        """Get health status directly from /health endpoints"""
        status = {}
        current_time = datetime.now().isoformat()
        
        for name, url in self.model_endpoints.items():
            try:
                # Direct health check call
                response = requests.get(f"{url}/health", timeout=3)
                if response.status_code == 200:
                    health_data = response.json()
                    self.last_updates[name] = current_time
                    status[name] = {
                        'status': health_data.get('status', 'unknown'),
                        'last_update': current_time,
                        'endpoint': url,
                        'details': health_data
                    }
                else:
                    status[name] = {
                        'status': 'unhealthy',
                        'last_update': self.last_updates.get(name),
                        'error': f"HTTP {response.status_code}"
                    }
            except Exception as e:
                status[name] = {
                    'status': 'unreachable',
                    'last_update': self.last_updates.get(name),
                    'error': str(e)
                }
        
        return status

    def check_model_health(self, model_name):
        """Check and cache health status with detailed components"""
        endpoint = self.model_endpoints.get(model_name)
        if not endpoint:
            return None
            
        try:
            response = requests.get(f"{endpoint}/health", timeout=3)
            if response.status_code == 200:
                health_data = response.json()
                self.health_cache[model_name] = health_data
                self.last_checked[model_name] = datetime.now().isoformat()
                return {
                    'status': 'healthy',
                    'details': health_data,
                    'endpoint': endpoint
                }
            else:
                return {
                    'status': 'unhealthy',
                    'error': f"HTTP {response.status_code}",
                    'endpoint': endpoint
                }
        except Exception as e:
            return {
                'status': 'unreachable',
                'error': str(e),
                'endpoint': endpoint
            }

    def test_model(self, model_name, input_data=None, file_path=None):
        """Test a model with proper response handling"""
        endpoint = self.model_endpoints.get(model_name)
        if not endpoint:
            return {'error': 'Model not configured'}
        
        # Determine the endpoint path based on model type
        if model_name == 'Phishing Detection':
            endpoint_path = '/scan-url'
        else:
            endpoint_path = '/predict'
        
        start_time = time.time()
        
        try:
            if file_path:  # For malware detection
                with open(file_path, 'rb') as f:
                    files = {'file': f}
                    response = requests.post(
                        f"{endpoint}{endpoint_path}",
                        files=files,
                        timeout=30
                    )
            else:  # For other models
                response = requests.post(
                    f"{endpoint}{endpoint_path}",
                    json=input_data or self.get_sample_input(model_name),
                    timeout=10
                )
            
            response.raise_for_status()
            return {
                'status': 'success',
                'data': response.json(),
                'response_time': time.time() - start_time,
                'model': model_name,
                'endpoint': endpoint
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'model': model_name,
                'endpoint': endpoint,
                'response_time': time.time() - start_time
            }

    def get_sample_input(self, model_name):
        """Return sample input based on model type"""
        if model_name == 'Anomaly Detection':
            return {
                'duration': 0,
                'protocol_type': 'tcp',
                'service': 'http',
                'flag': 'SF',
                'src_bytes': 100,
                'dst_bytes': 0,
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0
            }
        elif model_name == 'Phishing Detection':
            return {
                'url': 'https://example.com/login',
                'content': 'Please login to verify your account',
                'sender': 'support@example.com',
                'subject': 'Urgent: Account Verification Required'
            }
        elif model_name == 'Windows Log Analysis':
            return {
                'event_id': 4624,
                'log_type': 'Security',
                'source_ip': '192.168.1.100',
                'user': 'DOMAIN\\user',
                'timestamp': datetime.now().isoformat()
            }
        return {}