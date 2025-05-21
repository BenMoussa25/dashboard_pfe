import os
import random
import tempfile
import concurrent
from flask import Blueprint, render_template, jsonify, make_response, request, flash, redirect, url_for
from datetime import datetime, timedelta
from flask_jwt_extended import jwt_required

from flask_jwt_extended import current_user
import requests
from app.models import User, Incident, Enrichment, MLModel, LLMPrompt, AnalyticsLog
from app import db
from app.utils.ml_connector import MLModelConnector
from app.utils.llm_reporter import LLMReporter
from app.auth import role_required
import csv
from io import StringIO
from reportlab.pdfgen import canvas
from io import BytesIO
from app.utils.ml_monitor import ModelMonitor

from app.utils.settings import SettingsManager, init_default_settings

main_routes = Blueprint('main', __name__)

ml_connector = MLModelConnector()


model_monitors = {
    'Anomaly Detection': ModelMonitor('Anomaly Detection', "http://localhost:3000"),
    'Malware Detection': ModelMonitor('Malware Detection', "http://localhost:4000"),
    'Phishing Detection': ModelMonitor('Phishing Detection', "http://localhost:6000"),
    'Windows Log Analysis': ModelMonitor('Windows Log Analysis', "http://localhost:7000")
}

MONITORING_SERVICES = {
    'network_monitor': {
        'name': 'Network Host Monitor',
        'base_url': 'http://localhost:3333',
        'endpoints': {
            'status': '/status',
            'start': '/start',
            'stop': '/stop',
            'results': '/results'
        },
        'description': 'SIEM and log analysis'
    },
    'email_monitor': {
        'name': 'Email Security Monitor',
        'base_url': 'http://localhost:6666',
        'endpoints': {
            'status': '/status',
            'start': '/start',
            'stop': '/stop',
            'results': '/results'
        },
        'description': 'Email phishing and malware detection'
    },
    'wazuh_monitor': {
        'name': 'Wazuh Log Monitor',
        'base_url': 'http://localhost:7777',
        'endpoints': {
            'status': '/status',
            'start': '/start',
            'stop': '/stop',
            'results': '/results'
        },
        'description': 'Wazuh log analysis and threat detection'
    },
    'pe_monitor': {
        'name': 'PE File Monitor',
        'base_url': 'http://localhost:4444',
        'endpoints': {
            'status': '/status',
            'start': '/start',
            'stop': '/stop',
            'results': '/results'
        },
        'description': 'Windows PE file malware detection'
    }
}

def get_service_status_parallel(service_dict):
    """Get status of all services in parallel"""
    results = {}
    
    def get_single_status(service_id, service_info):
        status_url = f"{service_info['base_url']}{service_info['endpoints']['status']}"
        status = make_request(status_url)
        return service_id, status
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_service = {
            executor.submit(get_single_status, service_id, service_info): service_id
            for service_id, service_info in service_dict.items()
        }
        
        for future in concurrent.futures.as_completed(future_to_service):
            service_id, status = future.result()
            results[service_id] = {
                'name': service_dict[service_id]['name'],
                'description': service_dict[service_id]['description'],
                'status_data': status,
                'is_active': status.get('monitoring', {}).get('active', False) if 'error' not in status else False,
                'last_check': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    return results


def make_request(url, method='GET', timeout=5):
    """Make a request to a monitoring service with error handling"""
    try:
        if method.upper() == 'GET':
            response = requests.get(url, timeout=timeout)
        elif method.upper() == 'POST':
            response = requests.post(url, timeout=timeout)
        else:
            return {'error': f'Unsupported method: {method}'}
        
        return response.json()
    except requests.exceptions.ConnectionError:
        return {'error': 'Connection error', 'status': 'offline'}
    except requests.exceptions.Timeout:
        return {'error': 'Request timed out', 'status': 'timeout'}
    except Exception as e:
        print(f"Error making request to {url}: {str(e)}")
        return {'error': str(e), 'status': 'error'}

def create_incident_from_result(result, service_name):
    """Create an Incident object from monitoring result data"""
    # Parse the alert and result JSON strings
    alert_data = result.get('alert', {})
    result_data = result.get('result', {})
    
    # Determine severity based on rule level or score
    severity = 'Medium'  # Default severity
    if alert_data.get('rule', {}).get('level', 0) >= 10:
        severity = 'Critical'
    elif alert_data.get('rule', {}).get('level', 0) >= 7:
        severity = 'High'
    elif alert_data.get('rule', {}).get('level', 0) >= 5:
        severity = 'Medium'
    else:
        severity = 'Low'

    # Create new incident
    incident = Incident(
        timestamp=datetime.fromisoformat(alert_data.get('timestamp', datetime.now().isoformat())),
        source_ip=alert_data.get('source_ip', 'Unknown'),
        type=alert_data.get('rule', {}).get('description', '').split(':')[0] or 'Unknown',
        severity=severity,
        ml_model_name=service_name,
        confidence_score=result_data.get('confidence', 0.5),
        status='New',
        description=alert_data.get('rule', {}).get('description', ''),
        monitoring_system=service_name,
        raw_detection_data=result
    )
    
    return incident

def fetch_monitoring_results():
    """Fetch results from all monitoring services and create incidents"""
    logger.info("Fetching monitoring results and creating incidents...")

    created_incidents = 0

    for service_id, service_info in MONITORING_SERVICES.items():
        try:
            results_url = f"{service_info['base_url']}{service_info['endpoints']['results']}"
            response = make_request(results_url)

            if response and 'data' in response and 'results' in response['data']:
                for result in response['data']['results']:
                    incident = create_incident_from_result(result, service_info['name'])

                    # Check if this incident already exists
                    existing = Incident.query.filter_by(
                        timestamp=incident.timestamp,
                        source_ip=incident.source_ip,
                        type=incident.type
                    ).first()

                    if not existing:
                        db.session.add(incident)
                        created_incidents += 1

                        # Create analytics log entry for this incident
                        log = AnalyticsLog(
                            incident_id=incident.id,
                            event_type='creation',
                            analyst_id='system',  # System-generated incident
                            timestamp=datetime.utcnow()
                        )
                        db.session.add(log)
            # Handle email monitoring results format
            elif response and 'results' in response:
                for result in response['results']:
                    incident = create_incident_from_email_result(result, service_info['name'])
                    
                    # Check if this incident already exists
                    existing = Incident.query.filter_by(
                        timestamp=incident.timestamp,
                        source=incident.source,
                        type=incident.type
                    ).first()

                    if not existing and should_create_incident(result):
                        db.session.add(incident)
                        created_incidents += 1

                        # Create analytics log entry for this incident
                        log = AnalyticsLog(
                            incident_id=incident.id,
                            event_type='creation',
                            analyst_id='system',  # System-generated incident
                            timestamp=datetime.utcnow()
                        )
                        db.session.add(log)

        except Exception as e:
            logger.error(f"Error processing results from {service_id}: {str(e)}")

    try:
        if created_incidents > 0:
            db.session.commit()
            logger.info(f"Created {created_incidents} new incidents from monitoring results")
        else:
            logger.info("No new incidents to create")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving incidents to database: {str(e)}")

def create_incident_from_email_result(result, service_name):
    """Create an incident from an email monitoring result"""
    incident_type = "Suspicious Email"
    severity = "medium"  # Default severity
    
    # Determine if this is a phishing/malicious email
    if "result" in result and result["result"] != "Legitimate":
        incident_type = "Malicious Email"
        severity = "high"
    
    # Create the incident
    incident = Incident(
        timestamp=parse_timestamp(result.get("timestamp")),
        source=result.get("from", "Unknown Sender"),
        source_ip="",  # Email results may not have IP
        destination="",
        destination_port=0,
        protocol="SMTP",
        type=incident_type,
        severity=severity,
        service=service_name,
        status="new",
        details=json.dumps(result)
    )
    
    return incident

def create_incident_from_pe_result(result, service_name):
    """Create an incident from a PE file monitoring result"""
    file_info = result.get("file_info", {})
    analysis_result = result.get("analysis_result", {})
    
    incident_type = "Suspicious File"
    severity = "medium"  # Default severity
    
    # Determine if this file is malicious
    if analysis_result.get("malware_status", False) or analysis_result.get("verdict") != "Normal":
        incident_type = "Malicious File"
        severity = "high"
    
    # Create the incident
    incident = Incident(
        timestamp=datetime.utcnow(),  # PE results may not have timestamp
        source=file_info.get("filename", "Unknown File"),
        source_ip="",  # PE results don't have IP
        destination="",
        destination_port=0,
        protocol="FILE",
        type=incident_type,
        severity=severity,
        service=service_name,
        status="new",
        details=json.dumps(result)
    )
    
    return incident

def should_create_incident(result):
    """Determine if an incident should be created from the result"""
    # For email monitor, only create incidents for non-legitimate emails
    if "result" in result:
        return result["result"] != "Legitimate"
    
    # For PE monitor, only create incidents for malicious/suspicious files
    if "analysis_result" in result:
        analysis = result["analysis_result"]
        return analysis.get("malware_status", False) or analysis.get("verdict") != "Normal"
        
    # For Wazuh, the existing logic handles this
    return True

def parse_timestamp(timestamp_str):
    """Parse timestamp string to datetime object"""
    if not timestamp_str:
        return datetime.utcnow()
    
    try:
        return datetime.fromisoformat(timestamp_str)
    except (ValueError, TypeError):
        return datetime.utcnow()


@main_routes.route('/incidents')
@role_required('analyst')
def incidents():
    # Get results from each monitoring service
    all_incidents = []
    
    for service_id, service_info in MONITORING_SERVICES.items():
        try:
            results_url = f"{service_info['base_url']}{service_info['endpoints']['results']}"
            response = make_request(results_url)
            
            if response and 'data' in response and 'results' in response['data']:
                for result in response['data']['results']:
                    incident = create_incident_from_result(result, service_info['name'])
                    all_incidents.append(incident)
                    
                    # Save to database if it doesn't exist
                    existing = Incident.query.filter_by(
                        timestamp=incident.timestamp,
                        source_ip=incident.source_ip,
                        type=incident.type
                    ).first()
                    
                    if not existing:
                        db.session.add(incident)
        
        except Exception as e:
            print(f"Error processing results from {service_id}: {str(e)}")
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error saving incidents to database: {str(e)}")
    
    # Get all incidents from database, ordered by timestamp
    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    
    # Get services status
    services_status = get_service_status_parallel(MONITORING_SERVICES)
    
    # Combine all monitoring data
    all_monitoring = {
        'services': services_status
    }
    
    return render_template('incidents.html', 
                          incidents=incidents,
                          monitoring_data=all_monitoring,
                          now=datetime.now())

# Mock data generator (replace with your actual data sources)
def generate_mock_data():
    # Severity distribution
    severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
    severity_data = {s: random.randint(1, 50) for s in severities}
    
    # Alert types (from your 4 models)
    alert_types = {
        'Model 1 Threats': random.randint(5, 30),
        'Model 2 Anomalies': random.randint(5, 30),
        'Model 3 IoCs': random.randint(5, 30),
        'Model 4 Behaviors': random.randint(5, 30),
        'Other Alerts': random.randint(1, 15)
    }
    
    # Generate mock workload data
    analysts = ['Alex', 'Jordan', 'Taylor', 'Casey']
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri']
    workload = {
        analyst: {day: random.randint(0, 10) for day in days}
        for analyst in analysts
    }

    return {
        'severity': severity_data,
        'alert_types': alert_types,
        'workload': workload
    }

def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    if value is None:
        return ""
    return value.strftime(format)

main_routes.add_app_template_filter(format_datetime, 'format_datetime')

@main_routes.route('/dashboard')
@role_required('analyst')
def dashboard():
    # Get severity distribution
    severity_counts = db.session.query(
        Incident.severity,
        db.func.count(Incident.id)
    ).group_by(Incident.severity).all()
    severity_data = {sev: count for sev, count in severity_counts}
    
    # Get alert type distribution
    alert_type_counts = db.session.query(
        Incident.type,
        db.func.count(Incident.id)
    ).group_by(Incident.type).all()
    alert_data = {typ: count for typ, count in alert_type_counts}
    
    # Get time-based counts
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_alerts = Incident.query.filter(Incident.timestamp >= today_start).count()
    
    week_start = today_start - timedelta(days=today_start.weekday())
    week_alerts = Incident.query.filter(Incident.timestamp >= week_start).count()
    
    month_start = today_start.replace(day=1)
    month_alerts = Incident.query.filter(Incident.timestamp >= month_start).count()
    
    # Get REAL model status from ML Connector
    model_status = ml_connector.get_model_status()
    
    # Get recent incidents with LLM summaries
    recent_reports = Incident.query.filter(
        Incident.llm_summary.isnot(None)
    ).order_by(Incident.timestamp.desc()).limit(3).all()
    
    # Get workload data
    analysts = User.query.filter_by(role='analyst').all()
    workload_data = {
        analyst.username: {
            'Mon': Incident.query.filter_by(assigned_to=analyst.id, status='In Progress').count(),
            # Add other days as needed
        } for analyst in analysts
    }
    
    return render_template('dashboard.html',
        now=datetime.now(),
        workload_data=workload_data,
        severity_data=severity_data,
        alert_data=alert_data,
        today_alerts=today_alerts,
        week_alerts=week_alerts,
        month_alerts=month_alerts,
        model_status=model_status,
        recent_reports=recent_reports
    )

@main_routes.route('/incident/<incident_id>')
@role_required('analyst')
def incident_detail(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    enrichments = Enrichment.query.filter_by(incident_id=incident_id).all()
    
    # Convert enrichments to a more accessible format for the template
    enrichment_data = {e.source: e.data for e in enrichments}
    
    # Get LLM report if available
    llm_report = {
        'narrative': incident.llm_summary,
        'actions': []  # You might want to parse this from the summary
    } if incident.llm_summary else None
    
    # Get service monitoring data
    service_data = {}
    for service_id, service_info in MONITORING_SERVICES.items():
        try:
            results_url = f"{service_info['base_url']}{service_info['endpoints']['results']}"
            results = make_request(results_url)
            
            # Filter results to find entries relevant to this incident
            filtered_results = {}
            if 'data' in results and 'entries' in results['data']:
                filtered_results = [
                    entry for entry in results['data']['entries']
                    # Filter based on timestamp and other relevant fields if available
                    if entry.get('source_ip') == incident.source_ip or
                       (
                           'timestamp' in entry and 
                           datetime.fromisoformat(entry['timestamp']) >= incident.timestamp - timedelta(minutes=30) and
                           datetime.fromisoformat(entry['timestamp']) <= incident.timestamp + timedelta(minutes=30)
                       )
                ]
            
            if filtered_results:
                service_data[service_id] = {
                    'name': service_info['name'],
                    'results': filtered_results,
                    'count': len(filtered_results)
                }
        except Exception as e:
            print(f"Error getting service data for {service_id}: {str(e)}")
    
    # Initialize relevant_monitoring regardless of service_data content
    relevant_monitoring = {'services': service_data}
    
    random_values = {
        'anomaly_score': random.random(),
        'behavior_deviation': random.random(),
        'ioc_matches': random.randint(1, 5)
    }
    
    analysts = User.query.filter_by(role='analyst').all()
    return render_template('incident_detail.html', 
                          incident=incident,
                          enrichments=enrichment_data,
                          random_values=random_values,
                          llm_report=llm_report,
                          monitoring_data=relevant_monitoring,
                          now=datetime.now(),
                          analysts=analysts)

@main_routes.route('/incident/<incident_id>/update', methods=['POST'])
@jwt_required()  # Add this decorator
@role_required('analyst')
def update_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    new_status = request.form.get('status')
    
    # Log the status change
    log = AnalyticsLog(
        incident_id=incident.id,
        analyst_id=current_user.id,  # Now properly authenticated
        event_type='status_change',
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    
    incident.status = new_status
    db.session.commit()
    
    flash('Incident status updated', 'success')
    return redirect(url_for('main.incident_detail', incident_id=incident_id))

@main_routes.route('/incident/<incident_id>/assign/<user_id>', methods=['POST'])
@jwt_required()
@role_required('manager')
def assign_incident(incident_id, user_id):
    incident = Incident.query.get_or_404(incident_id)
    user = User.query.get_or_404(user_id)
    
    
    incident.assigned_to = user.id
    db.session.commit()
    
    # Log the assignment
    log = AnalyticsLog(
        incident_id=incident.id,
        analyst_id=current_user.id,
        event_type='assignment',
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()

    flash(f'Incident {incident_id} assigned to {user.username}', 'success')
    return redirect(url_for('main.incident_detail', incident_id=incident_id))

@main_routes.route('/api/incidents/ingest', methods=['POST'])
def ingest_incident():
    """Endpoint for ML models to submit detected incidents"""
    data = request.json
    
    # Validate required fields
    required_fields = ['model_name', 'alert_type', 'severity', 'confidence', 'description']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        # Create new incident
        incident = Incident(
            source_ip=data.get('source_ip', 'Unknown'),
            type=data['alert_type'],
            severity=data['severity'],
            ml_model_name=data['model_name'],
            confidence_score=data['confidence'],
            description=data['description'],
            status='New'
        )
        
        db.session.add(incident)
        db.session.commit()
        
        # Log the creation
        log = AnalyticsLog(
            incident_id=incident.id,
            event_type='creation',
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'incident_id': incident.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@main_routes.route('/api/refresh-data')
@role_required('admin')
def refresh_data():
    data = generate_mock_data()
    return jsonify(data)

@main_routes.route('/analytics')
@role_required('analyst')
def analytics():
    # Calculate MTTR (Mean Time To Resolution)
    resolved_incidents = Incident.query.filter_by(status='Closed').all()
    mttr_data = {}
    
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        incidents = [i for i in resolved_incidents if i.severity == severity]
        if incidents:
            avg_seconds = sum(
                (log.timestamp - incident.timestamp).total_seconds()
                for incident in incidents
                for log in incident.analytics_logs
                if log.event_type == 'status_change' and incident.status == 'Closed'
            ) / len(incidents)
            mttr_data[severity] = timedelta(seconds=avg_seconds)
        else:
            mttr_data[severity] = timedelta(0)
    
    # Get top alert types
    top_alerts = db.session.query(
        Incident.type,
        db.func.count(Incident.id)
    ).group_by(Incident.type).order_by(db.func.count(Incident.id).desc()).limit(5).all()
    top_alerts = [{'type': typ, 'count': cnt} for typ, cnt in top_alerts]
    
    # Get volume trends (last 7 days)
    days = []
    counts = []
    for i in range(6, -1, -1):
        day = datetime.now() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day.replace(hour=23, minute=59, second=59, microsecond=999)
        count = Incident.query.filter(
            Incident.timestamp >= day_start,
            Incident.timestamp <= day_end
        ).count()
        days.append(day.strftime('%a'))
        counts.append(count)
    
    volume_trends = {'days': days, 'counts': counts}
    
    # Get analyst performance
    analysts = User.query.filter_by(role='analyst').all()
    analyst_performance = {}
    for analyst in analysts:
        resolved = Incident.query.filter_by(assigned_to=analyst.id, status='Closed').count()
        false_positives = Incident.query.filter_by(assigned_to=analyst.id, status='False Positive').count()
        
        # Calculate MTTR for this analyst
        analyst_incidents = Incident.query.filter_by(assigned_to=analyst.id, status='Closed').all()
        if analyst_incidents:
            avg_seconds = sum(
                (log.timestamp - incident.timestamp).total_seconds()
                for incident in analyst_incidents
                for log in incident.analytics_logs
                if log.event_type == 'status_change' and incident.status == 'Closed'
            ) / len(analyst_incidents)
            mttr = timedelta(seconds=avg_seconds)
        else:
            mttr = timedelta(0)
        
        analyst_performance[analyst.username] = {
            'resolved': resolved,
            'mttr': mttr,
            'false_positives': false_positives
        }
    
    # Get false positives by model
    false_positives = db.session.query(
        Incident.ml_model_name,
        db.func.count(Incident.id)
    ).filter_by(status='False Positive').group_by(Incident.ml_model_name).all()
    false_positives = {model: count for model, count in false_positives}
    
    return render_template('analytics.html',
                         mttr_data=mttr_data,
                         top_alerts=top_alerts,
                         volume_trends=volume_trends,
                         analyst_performance=analyst_performance,
                         false_positives=false_positives)

@main_routes.route('/analytics/export/csv')
@role_required('analyst')
def export_analytics_csv():
    # Generate CSV data
    data = [
        ['Metric', 'Value'],
        ['MTTR Critical', '2.5 hours'],
        ['MTTR High', '4.2 hours'],
        ['Top Alert Type', 'Phishing (45)'],
        ['Weekly Volume', '663 alerts']
    ]
    
    # Create CSV response
    si = StringIO()
    cw = csv.writer(si)
    cw.writerows(data)
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=analytics_export.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@main_routes.route('/analytics/export/pdf')
@role_required('analyst')
def export_analytics_pdf():
    # Generate PDF
    from io import BytesIO
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    
    # PDF content
    p.drawString(100, 750, "SOC Analytics Report")
    p.drawString(100, 730, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    p.drawString(100, 700, "Key Metrics:")
    p.drawString(120, 680, "- MTTR Critical: 2.5 hours")
    p.drawString(120, 660, "- Top Alert Type: Phishing")
    p.drawString(120, 640, "- Weekly Volume: 663 alerts")
    
    p.showPage()
    p.save()
    
    # Return PDF
    buffer.seek(0)
    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=analytics_report.pdf'
    return response

@main_routes.route('/workload')
@role_required('manager')
def workload():
    # Get all analysts
    analysts = User.query.filter_by(role='analyst').all()
    
    # Get the current date and calculate the week start (Monday)
    today = datetime.now().date()
    week_start = today - timedelta(days=today.weekday())
    
    analyst_data = []
    
    for analyst in analysts:
        # Get open incidents count
        open_incidents = Incident.query.filter_by(
            assigned_to=analyst.id
        ).filter(Incident.status.in_(['New', 'In Progress'])).count()
        
        # Get incidents assigned this week
        weekly_assigned = Incident.query.filter(
            Incident.assigned_to == analyst.id,
            Incident.timestamp >= week_start
        ).count()
        
        # Get incidents resolved this week
        weekly_resolved = Incident.query.join(AnalyticsLog).filter(
            Incident.assigned_to == analyst.id,
            Incident.status == 'Closed',
            AnalyticsLog.event_type == 'status_change',
            AnalyticsLog.timestamp >= week_start
        ).count()
        
        # Calculate capacity (you can adjust this formula as needed)
        capacity = 20  # Base capacity
        adjusted_capacity = capacity - open_incidents
        
        analyst_data.append({
            'id': analyst.id,
            'name': analyst.username,
            'open_incidents': open_incidents,
            'weekly_assigned': weekly_assigned,
            'weekly_resolved': weekly_resolved,
            'capacity': capacity,
            'adjusted_capacity': adjusted_capacity if adjusted_capacity > 0 else 0
        })
    
    # Get unassigned incidents (new ones first)
    unassigned_incidents = Incident.query.filter_by(
        assigned_to=None
    ).filter(Incident.status == 'New').order_by(Incident.timestamp.desc()).all()
    
    return render_template('workload.html',
                         analysts=analyst_data,
                         unassigned_incidents=unassigned_incidents)

@main_routes.route('/api/analysts/<analyst_id>')
@role_required('manager')
def get_analyst_details(analyst_id):
    analyst = User.query.get_or_404(analyst_id)
    
    # Get open incidents count
    open_incidents = Incident.query.filter_by(
        assigned_to=analyst.id
    ).filter(Incident.status.in_(['New', 'In Progress'])).count()
    
    # Get this week's activity
    week_start = datetime.now().date() - timedelta(days=datetime.now().weekday())
    weekly_assigned = Incident.query.filter(
        Incident.assigned_to == analyst.id,
        Incident.timestamp >= week_start
    ).count()
    
    weekly_resolved = Incident.query.join(AnalyticsLog).filter(
        Incident.assigned_to == analyst.id,
        Incident.status == 'Closed',
        AnalyticsLog.event_type == 'status_change',
        AnalyticsLog.timestamp >= week_start
    ).count()
    
    # Get recent activity (last 5 actions)
    recent_activity = []
    logs = AnalyticsLog.query.filter_by(analyst_id=analyst.id).order_by(AnalyticsLog.timestamp.desc()).limit(5).all()
    for log in logs:
        if log.event_type == 'status_change':
            recent_activity.append(f"Changed status of INC-{log.incident_id[:8]} on {log.timestamp.strftime('%m/%d %H:%M')}")
        elif log.event_type == 'assignment':
            recent_activity.append(f"Assigned to INC-{log.incident_id[:8]} on {log.timestamp.strftime('%m/%d %H:%M')}")
    
    return jsonify({
        'id': analyst.id,
        'name': analyst.username,
        'open_incidents': open_incidents,
        'weekly_assigned': weekly_assigned,
        'weekly_resolved': weekly_resolved,
        'capacity': 20,  # Same as in workload route
        'adjusted_capacity': max(0, 20 - open_incidents),
        'recent_activity': recent_activity
    })

@main_routes.route('/workload/auto-assign', methods=['POST'])
@role_required('manager')
def auto_assign_incidents():
    # Check if fair distribution is enabled
    fair_distribution = SettingsManager.get_setting('fair_distribution_enabled', True)
    analyst_capacity = SettingsManager.get_setting('analyst_capacity', 20)
    
    # Get all unassigned incidents
    unassigned_incidents = Incident.query.filter_by(
        assigned_to=None
    ).filter(Incident.status == 'New').order_by(
        Incident.severity.desc(),  # Critical first
        Incident.timestamp.asc()    # Oldest first
    ).all()
    
    if not unassigned_incidents:
        return jsonify({
            'status': 'success',
            'message': 'No unassigned incidents',
            'assigned_count': 0
        })
    
    # Get all analysts with capacity
    analysts = User.query.filter_by(role='analyst').all()
    analyst_capacity_list = []
    
    for analyst in analysts:
        open_incidents = Incident.query.filter_by(
            assigned_to=analyst.id
        ).filter(Incident.status.in_(['New', 'In Progress'])).count()
        capacity = max(0, analyst_capacity - open_incidents)
        if capacity > 0:
            analyst_capacity_list.append({
                'id': analyst.id,
                'name': analyst.username,
                'capacity': capacity,
                'current_load': open_incidents
            })
    
    if not analyst_capacity_list:
        return jsonify({
            'status': 'error',
            'message': 'No analysts with available capacity',
            'assigned_count': 0
        })
    
    # Distribute incidents
    assigned_count = 0
    
    if fair_distribution:
        # Fair distribution - round robin based on capacity
        analyst_capacity_list.sort(key=lambda x: x['current_load'])
        
        for incident in unassigned_incidents:
            if analyst_capacity_list[0]['capacity'] > 0:
                assign_to_analyst(incident, analyst_capacity_list[0]['id'])
                analyst_capacity_list[0]['current_load'] += 1
                analyst_capacity_list[0]['capacity'] -= 1
                assigned_count += 1
                
                # Re-sort to maintain fair distribution
                analyst_capacity_list.sort(key=lambda x: x['current_load'])
    else:
        # Simple distribution - assign to first available analyst
        for incident in unassigned_incidents:
            for analyst in analyst_capacity_list:
                if analyst['capacity'] > 0:
                    assign_to_analyst(incident, analyst['id'])
                    analyst['current_load'] += 1
                    analyst['capacity'] -= 1
                    assigned_count += 1
                    break
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': f'Assigned {assigned_count} incidents',
        'assigned_count': assigned_count,
        'fair_distribution': fair_distribution
    })

def assign_to_analyst(incident, analyst_id):
    incident.assigned_to = analyst_id
    incident.status = 'In Progress'
    
    # Log the assignment
    log = AnalyticsLog(
        incident_id=incident.id,
        analyst_id=current_user.id,
        event_type='assignment',
        timestamp=datetime.utcnow()
    )
    db.session.add(log)

@main_routes.route('/workload/assign/<user_id>/<incident_id>')
@role_required('manager')
def assign_incident_from_workload(user_id, incident_id):
    incident = Incident.query.get_or_404(incident_id)
    user = User.query.get_or_404(user_id)
    
    incident.assigned_to = user.id
    incident.status = 'In Progress'
    
    # Log the assignment
    log = AnalyticsLog(
        incident_id=incident.id,
        analyst_id=current_user.id,  # The manager who made the assignment
        event_type='assignment',
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': f'Incident {incident_id} assigned to {user.username}',
        'analyst': user.username,
        'incident': incident_id
    })

@main_routes.route('/workload/toggle-fair-distribution', methods=['POST'])
@role_required('manager')
def toggle_fair_distribution():
    current_setting = SettingsManager.get_setting('fair_distribution_enabled', True)
    new_setting = not current_setting
    
    SettingsManager.set_setting(
        name='fair_distribution_enabled',
        value=new_setting,
        description='Whether to enable fair distribution of incidents among analysts'
    )
    
    return jsonify({
        'status': 'success',
        'message': f'Fair distribution {"enabled" if new_setting else "disabled"}',
        'new_status': new_setting
    })

@main_routes.route('/api/workload/settings')
@role_required('manager')
def get_workload_settings():
    return jsonify({
        'fair_distribution_enabled': SettingsManager.get_setting('fair_distribution_enabled', True),
        'analyst_capacity': SettingsManager.get_setting('analyst_capacity', 20)
    })

@main_routes.route('/ml-models')
@role_required('admin')
def ml_models():
    models = MLModel.query.all()
    print(f"Models: {models}")
    # Get live status from connector
    model_status = ml_connector.get_model_status()
    return render_template('ml_models.html', 
                         models=models,
                         model_status=model_status)

@main_routes.route('/api/model-metrics')
@role_required('admin')
def get_model_metrics():
    metrics = {name: monitor.get_metrics() for name, monitor in model_monitors.items()}
    return jsonify(metrics)

@main_routes.route('/api/ml-models/<model_id>/test', methods=['POST'])
@role_required('admin')
def test_model(model_id):
    model = MLModel.query.get_or_404(model_id)
    
    try:
        # Get input data
        if request.content_type == 'multipart/form-data':
            file = request.files.get('file')
            if not file:
                return jsonify({'error': 'No file uploaded'}), 400
            
            temp_path = os.path.join(tempfile.gettempdir(), file.filename)
            file.save(temp_path)
            
            try:
                result = ml_connector.test_model(model.name, file_path=temp_path)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            input_data = request.get_json()
            if not input_data and request.args.get('use_sample') == 'true':
                # Use sample data based on model type
                if model.name == 'Phishing Detection':
                    input_data = {
                        "url": "https://example.com/login",
                        "content": "Please login to verify your account",
                        "sender": "support@example.com",
                        "subject": "Urgent: Account Verification Required"
                    }
                elif model.name == 'Windows Log Analysis':
                    input_data = {
                        "event_id": 4624,
                        "log_type": "Security",
                        "source_ip": "192.168.1.100",
                        "user": "DOMAIN\\user",
                        "timestamp": datetime.now().isoformat()
                    }
                else:  # Default sample for anomaly detection
                    input_data = {
                        "duration": 0,
                        "protocol_type": "tcp",
                        "service": "http",
                        "flag": "SF",
                        "src_bytes": 100,
                        "dst_bytes": 0,
                        "land": 0,
                        "wrong_fragment": 0,
                        "urgent": 0
                    }
            
            if not input_data:
                return jsonify({'error': 'No input data provided'}), 400
                
            result = ml_connector.test_model(model.name, input_data=input_data)

        # Debug print the raw response
        print(f"Raw model response: {result}")

        # Handle different response formats
        if model.name == 'Phishing Detection':
            # Phishing model specific response handling
            prediction_data = result.get('data', {})
            is_phishing = prediction_data.get('is_phishing', False)
            confidence = prediction_data.get('confidence', 0)
            features = {
                'url': prediction_data.get('url'),
                'score': prediction_data.get('score'),
                'reasons': prediction_data.get('reasons', [])
            }
        else:
            # Standard response handling for other models
            model_data = result.get('data', {})
            confidence = model_data.get('confidence', 0)
            features = model_data.get('features', input_data if input_data else {})

        return jsonify({
            'status': 'success',
            'prediction': {
                'confidence': float(confidence),
                'features': features,
                'is_anomaly': float(confidence) > 0.95,
                'is_phishing': is_phishing if model.name == 'Phishing Detection' else None
            },
            'model_endpoint': model.endpoint,
            'response_time': result.get('response_time', 0)
        })

    except Exception as e:
        print(f"Error testing model: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'message': 'Failed to process model test'
        }), 500
    
    
@main_routes.route('/api/ml-models/<model_id>/health')
def get_model_health(model_id):
    model = MLModel.query.get_or_404(model_id)
    health_data = ml_connector.check_model_health(model.name)
    
    if not health_data:
        return jsonify({'error': 'Model not found'}), 404
    
    return jsonify(health_data)

# Add new endpoint for model predictions
@main_routes.route('/api/ml-models/predict', methods=['POST'])
@role_required('analyst')
def make_prediction():
    data = request.json
    model_type = data.get('model_type')
    input_data = data.get('input_data')
    
    try:
        if model_type == 'anomaly':
            result = ml_connector.detect_anomaly(input_data)
        elif model_type == 'malware':
            # For malware, expect a file upload instead
            return jsonify({
                'status': 'error',
                'message': 'Use /malware/scan endpoint for file uploads'
            }), 400
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid model type'
            }), 400
        
        return jsonify({
            'status': 'success',
            'result': result
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@main_routes.route('/llm-config')
@role_required('admin')
def llm_config():
    prompts = LLMPrompt.query.all()
    providers = ['OpenAI', 'Anthropic', 'Llama 2', 'Mistral']  # Could also come from DB
    
    # Convert prompts to template format
    prompt_templates = {
        prompt.type: {
            'template': prompt.prompt_text,
            'provider': prompt.llm_provider
        } for prompt in prompts
    }
    
    return render_template('llm_config.html', 
                         providers=providers,
                         prompt_templates=prompt_templates)

# API endpoints for ML Models
@main_routes.route('/api/ml-models/<model_id>/toggle', methods=['POST'])
@role_required('admin')
def toggle_model(model_id):
    model = MLModel.query.get_or_404(model_id)
    model.is_active = not model.is_active
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': f'Model {model.name} status toggled',
        'new_status': 'active' if model.is_active else 'inactive'
    })

# API endpoints for LLM Config
@main_routes.route('/api/llm-config/provider', methods=['POST'])
def update_llm_provider():
    new_provider = request.json.get('provider')
    # In a real app, this would save to config
    return jsonify({
        'status': 'success',
        'message': f'LLM provider updated to {new_provider}',
        'provider': new_provider
    })

@main_routes.route('/api/llm-config/prompt', methods=['POST'])
@role_required('admin')
def update_prompt_template():
    alert_type = request.json.get('alert_type')
    prompt_text = request.json.get('prompt_text')
    provider = request.json.get('provider')
    
    prompt = LLMPrompt.query.filter_by(type=alert_type).first()
    if prompt:
        prompt.prompt_text = prompt_text
        prompt.llm_provider = provider
    else:
        prompt = LLMPrompt(
            type=alert_type,
            prompt_text=prompt_text,
            llm_provider=provider
        )
        db.session.add(prompt)
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': f'Updated {alert_type} prompt template',
        'alert_type': alert_type
    })

@main_routes.route('/monitoring')
@role_required('admin')
def monitoring_dashboard():
    """Main monitoring dashboard displaying all services"""
    services_status = get_service_status_parallel(MONITORING_SERVICES)
    return render_template('monitoring_dashboard.html', 
                          services=services_status, 
                          now=datetime.now())

@main_routes.route('/api/monitoring/all/status')
@jwt_required()
@role_required('admin')
def get_all_status():
    """Get status of all monitoring services"""
    services_status = get_service_status_parallel(MONITORING_SERVICES)
    return jsonify({
        'status': 'success',
        'data': services_status,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@main_routes.route('/api/monitoring/<service_id>/status')
@jwt_required()
@role_required('admin')
def get_service_status(service_id):
    """Get status of a specific monitoring service"""
    if service_id not in MONITORING_SERVICES:
        return jsonify({'error': 'Service not found'}), 404
    
    service = MONITORING_SERVICES[service_id]
    status_url = f"{service['base_url']}{service['endpoints']['status']}"
    status = make_request(status_url)
    
    return jsonify({
        'status': 'success',
        'service_id': service_id,
        'service_name': service['name'],
        'data': status,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@main_routes.route('/api/monitoring/<service_id>/start', methods=['POST'])
@jwt_required()
@role_required('admin')
def start_service(service_id):
    """Start a monitoring service"""
    if service_id not in MONITORING_SERVICES:
        return jsonify({'error': 'Service not found'}), 404
    
    service = MONITORING_SERVICES[service_id]
    start_url = f"{service['base_url']}{service['endpoints']['start']}"
    result = make_request(start_url, method='POST')
    
    return jsonify({
        'status': 'success',
        'service_id': service_id,
        'service_name': service['name'],
        'data': result,
        'message': f"{service['name']} started successfully" if 'error' not in result else result['error'],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@main_routes.route('/api/monitoring/<service_id>/stop', methods=['POST'])
@jwt_required()
@role_required('admin')
def stop_service(service_id):
    """Stop a monitoring service"""
    if service_id not in MONITORING_SERVICES:
        return jsonify({'error': 'Service not found'}), 404
    
    service = MONITORING_SERVICES[service_id]
    stop_url = f"{service['base_url']}{service['endpoints']['stop']}"
    result = make_request(stop_url, method='POST')
    
    return jsonify({
        'status': 'success',
        'service_id': service_id,
        'service_name': service['name'],
        'data': result,
        'message': f"{service['name']} stopped successfully" if 'error' not in result else result['error'],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@main_routes.route('/api/monitoring/<service_id>/results')
@jwt_required()
@role_required('analyst')
def get_service_results(service_id):
    """Get results from a monitoring service"""
    if service_id not in MONITORING_SERVICES:
        return jsonify({'error': 'Service not found'}), 404

    service = MONITORING_SERVICES[service_id]
    results_url = f"{service['base_url']}{service['endpoints']['results']}"
    results = make_request(results_url)
    
    # Format results based on service type
    formatted_results = {
        'status': 'success',
        'service_id': service_id,
        'service_name': service['name'],
        'data': results,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # For email monitor, add additional formatting
    if service_id == 'email_monitor' and results and 'results' in results:
        formatted_results['count'] = len(results['results'])
        # Add any email-specific formatting here if needed
    
    # For PE monitor, add additional formatting
    if service_id == 'pe_monitor' and results and 'results' in results:
        formatted_results['count'] = len(results['results'])
        # Add any PE-specific formatting here if needed

    return jsonify(formatted_results)


@main_routes.route('/api/monitoring/all/start', methods=['POST'])
@jwt_required()
@role_required('admin')
def start_all_services():
    """Start all monitoring services"""
    results = {}
    
    for service_id, service in MONITORING_SERVICES.items():
        start_url = f"{service['base_url']}{service['endpoints']['start']}"
        result = make_request(start_url, method='POST')
        results[service_id] = {
            'name': service['name'],
            'result': result,
            'success': 'error' not in result
        }
    
    return jsonify({
        'status': 'success',
        'data': results,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@main_routes.route('/api/monitoring/all/stop', methods=['POST'])
@jwt_required()
@role_required('admin')
def stop_all_services():
    """Stop all monitoring services"""
    results = {}
    
    for service_id, service in MONITORING_SERVICES.items():
        stop_url = f"{service['base_url']}{service['endpoints']['stop']}"
        result = make_request(stop_url, method='POST')
        results[service_id] = {
            'name': service['name'],
            'result': result,
            'success': 'error' not in result
        }
    
    return jsonify({
        'status': 'success',
        'data': results,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@main_routes.route('/api/monitoring/all/results')
@jwt_required()
@role_required('analyst')
def get_all_results():
    """Get results from all monitoring services"""
    results = {}
    
    for service_id, service in MONITORING_SERVICES.items():
        results_url = f"{service['base_url']}{service['endpoints']['results']}"
        service_results = make_request(results_url)
        results[service_id] = {
            'name': service['name'],
            'data': service_results,
            'success': 'error' not in service_results
        }
    
    return jsonify({
        'status': 'success',
        'data': results,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })