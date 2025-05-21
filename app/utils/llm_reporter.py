class LLMReporter:
    def get_recent_reports(self, limit=5):
        # Replace with actual LLM report retrieval
        return [
            {
                'title': 'Phishing Campaign Detected',
                'summary': 'Model 1 identified a new phishing campaign',
                'timestamp': '2023-11-15 09:15:00',
                'severity': 'High'
            },
            {
                'title': 'Unusual Data Exfiltration',
                'summary': 'Model 3 detected anomalous data transfer',
                'timestamp': '2023-11-15 08:30:00',
                'severity': 'Critical'
            }
        ][:limit]