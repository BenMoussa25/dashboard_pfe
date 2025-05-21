# ml_monitor.py
import time
from datetime import datetime
import psutil
import requests

class ModelMonitor:
    def __init__(self, model_name, model_url):
        self.model_name = model_name
        self.model_url = model_url
        self.endpoint = model_url
        self.metrics = {
            'uptime': 0,
            'response_time': 0,
            'success_rate': 1.0,
            'error_count': 0,
            'request_count': 0,
            'last_error': None,
            'cpu_usage': 0,
            'memory_usage': 0
        }
        self.start_time = datetime.now()

    def start(self):
        """Start the monitoring system"""
        response = requests.post(f"{self.endpoint}/start")
        response.raise_for_status()
        return response.json()
    
    def stop(self):
        """Stop the monitoring system"""
        response = requests.post(f"{self.endpoint}/stop")
        response.raise_for_status()
        return response.json()
    
    def get_status(self):
        """Get current status of the monitoring system"""
        try:
            response = requests.get(f"{self.endpoint}/status", timeout=5)
            response.raise_for_status()
            status = response.json()
            
            # Calculate error rate if available
            if 'total_requests' in status and 'failed_requests' in status:
                status['error_rate'] = status['failed_requests'] / max(1, status['total_requests'])
            
            return {
                'online': True,
                'last_active': datetime.now().isoformat(),
                **status
            }
        except requests.RequestException as e:
            return {
                'online': False,
                'error': str(e),
                'last_active': None
            }
    
    def update_metrics(self):
        """Collect and update monitoring metrics"""
        try:
            # Get system metrics
            process = psutil.Process()
            self.metrics['cpu_usage'] = process.cpu_percent()
            self.metrics['memory_usage'] = process.memory_info().rss
            
            # Calculate uptime
            self.metrics['uptime'] = (datetime.now() - self.start_time).total_seconds()
            
            # Test endpoint response
            start = time.time()
            response = requests.get(f"{self.model_url}/status", timeout=5)
            response_time = (time.time() - start) * 1000  # in ms
            
            self.metrics['request_count'] += 1
            self.metrics['response_time'] = (
                (self.metrics['response_time'] * (self.metrics['request_count'] - 1) + response_time) 
                / self.metrics['request_count']
            )
            
            if response.status_code != 200:
                self.metrics['error_count'] += 1
                self.metrics['last_error'] = str(response.content)
            
            self.metrics['success_rate'] = (
                1 - (self.metrics['error_count'] / self.metrics['request_count'])
            )
            
        except Exception as e:
            self.metrics['error_count'] += 1
            self.metrics['last_error'] = str(e)
            self.metrics['success_rate'] = (
                1 - (self.metrics['error_count'] / self.metrics['request_count'])
            )

    def get_metrics(self):
        """Get performance metrics from the monitoring system"""
        try:
            response = requests.get(f"{self.endpoint}/metrics", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {
                'error': str(e),
                'online': False
            }