# from flask import Flask, request, jsonify
# import os
# import re
# import requests
# import base64
# from werkzeug.utils import secure_filename
# from dotenv import load_dotenv
# from email import policy
# from email.parser import BytesParser
#
# app = Flask(__name__)
# load_dotenv()
#
# # Configuration
# app.config['UPLOAD_FOLDER'] = 'uploads/'
# app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
# ALLOWED_EXTENSIONS = {'eml'}
#
# # Ensure upload folder exists
# os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
#
# # Get API key from environment
# VT_API_KEY = os.getenv('VT_API_KEY')
#
# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#
# def extract_email_content(filepath):
#     """Extract content from .eml file"""
#     try:
#         with open(filepath, 'rb') as f:
#             msg = BytesParser(policy=policy.default).parse(f)
#             body = msg.get_body(preferencelist=('plain'))
#             if body:
#                 return body.get_content()
#             else:
#                 return ''
#     except Exception as e:
#         print(f"Error extracting email content: {e}")
#         return ''
#
# def extract_urls(text):
#     """Extract URLs from email content"""
#     url_pattern = re.compile(r'https?://\S+')
#     urls = re.findall(url_pattern, text)
#     return urls
#
# def encode_url_for_vt(url):
#     """Encode URL for VirusTotal API"""
#     url_bytes = url.encode('utf-8')
#     encoded = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')
#     return encoded
#
# def scan_urls_virustotal(urls):
#     """Scan URLs using VirusTotal API"""
#     if not VT_API_KEY:
#         return {'error': 'VirusTotal API key not configured'}
#
#     headers = {'x-apikey': VT_API_KEY}
#     results = []
#     is_malicious = False
#
#     for url in urls:
#         try:
#             # First, try to get existing analysis
#             encoded_url = encode_url_for_vt(url)
#             response = requests.get(
#                 f'https://www.virustotal.com/api/v3/urls/{encoded_url}',
#                 headers=headers,
#                 timeout=10
#             )
#
#             if response.status_code == 200:
#                 data = response.json()
#                 stats = data['data']['attributes']['last_analysis_stats']
#                 malicious_count = stats.get('malicious', 0)
#                 suspicious_count = stats.get('suspicious', 0)
#
#                 if malicious_count > 0 or suspicious_count > 2:
#                     is_malicious = True
#                     status = f"Malicious ({malicious_count} detections)"
#                 else:
#                     status = "Clean"
#
#                 results.append({
#                     'url': url,
#                     'status': status,
#                     'malicious': malicious_count,
#                     'suspicious': suspicious_count
#                 })
#
#             elif response.status_code == 404:
#                 # URL not in database, submit for analysis
#                 submit_response = requests.post(
#                     'https://www.virustotal.com/api/v3/urls',
#                     headers=headers,
#                     data={'url': url},
#                     timeout=10
#                 )
#
#                 if submit_response.status_code == 200:
#                     results.append({
#                         'url': url,
#                         'status': 'Submitted for analysis',
#                         'malicious': 0,
#                         'suspicious': 0
#                     })
#                 else:
#                     results.append({
#                         'url': url,
#                         'status': 'Error submitting',
#                         'malicious': 0,
#                         'suspicious': 0
#                     })
#             else:
#                 results.append({
#                     'url': url,
#                     'status': f'API Error: {response.status_code}',
#                     'malicious': 0,
#                     'suspicious': 0
#                 })
#
#         except requests.RequestException as e:
#             results.append({
#                 'url': url,
#                 'status': f'Network Error: {str(e)}',
#                 'malicious': 0,
#                 'suspicious': 0
#             })
#
#     return {'is_malicious': is_malicious, 'url_results': results}
#
# def analyze_email_content(content):
#     """Simple phishing detection based on common patterns"""
#     suspicious_phrases = [
#         'urgent action required',
#         'verify your account',
#         'click here immediately',
#         'suspended account',
#         'confirm your identity',
#         'update payment information',
#         'act now',
#         'limited time offer',
#         'congratulations you have won'
#     ]
#
#     content_lower = content.lower()
#     detected_phrases = []
#
#     for phrase in suspicious_phrases:
#         if phrase in content_lower:
#             detected_phrases.append(phrase)
#
#     return {
#         'is_suspicious': len(detected_phrases) > 0,
#         'detected_phrases': detected_phrases,
#         'suspicion_score': len(detected_phrases)
#     }
#
# @app.route('/api/analyze', methods=['POST'])
# def analyze_email():
#     """Main endpoint to analyze uploaded email file"""
#     try:
#         # Check if file is present
#         if 'file' not in request.files:
#             return jsonify({'error': 'No file uploaded'}), 400
#
#         file = request.files['file']
#
#         if file.filename == '':
#             return jsonify({'error': 'No file selected'}), 400
#
#         if not allowed_file(file.filename):
#             return jsonify({'error': 'Invalid file type. Please upload a .eml file'}), 400
#
#         # Save file
#         filename = secure_filename(file.filename)
#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#         file.save(filepath)
#
#         # Extract email content
#         email_content = extract_email_content(filepath)
#
#         if not email_content:
#             # Clean up file
#             os.remove(filepath)
#             return jsonify({'error': 'Could not extract content from email file'}), 400
#
#         # Extract URLs
#         urls = extract_urls(email_content)
#
#         # Analyze with VirusTotal
#         vt_results = scan_urls_virustotal(urls)
#
#         # Analyze email content for suspicious patterns
#         content_analysis = analyze_email_content(email_content)
#
#         # Determine final verdict
#         is_phishing = vt_results.get('is_malicious', False) or content_analysis['is_suspicious']
#
#         reasons = []
#         if vt_results.get('is_malicious'):
#             reasons.append('Contains malicious URLs')
#         if content_analysis['is_suspicious']:
#             reasons.append(f'Contains suspicious phrases: {", ".join(content_analysis["detected_phrases"])}')
#         if not reasons:
#             reasons.append('No suspicious content detected')
#
#         result = {
#             'is_phishing': is_phishing,
#             'verdict': 'PHISHING DETECTED' if is_phishing else 'EMAIL APPEARS SAFE',
#             'confidence': 'High' if len(reasons) > 1 else 'Medium',
#             'reasons': reasons,
#             'url_analysis': vt_results.get('url_results', []),
#             'urls_found': len(urls),
#             'content_analysis': content_analysis
#         }
#
#         # Clean up uploaded file
#         try:
#             os.remove(filepath)
#         except:
#             pass
#
#         return jsonify({'success': True, 'result': result})
#
#     except Exception as e:
#         return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
#
# @app.route('/health', methods=['GET'])
# def health_check():
#     """Simple health check endpoint"""
#     return jsonify({'status': 'healthy', 'message': 'Phish Analyzer API is running'})
#
# def find_free_port():
#     """Find a free port to run the Flask app"""
#     import socket
#     for port in range(5001, 5010):  # Try ports 5001-5009
#         try:
#             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#                 s.bind(('localhost', port))
#                 return port
#         except OSError:
#             continue
#     return 5001  # Default fallback
#
# if __name__ == '__main__':
#     port = find_free_port()
#     print(f"Starting Flask server on port {port}")
#     print(f"Update your Next.js API to use: http://localhost:{port}/api/analyze")
#     app.run(debug=True, host='0.0.0.0', port=port)



from flask import Flask, request, jsonify
import os
import re
import requests
import base64
import time
import socket
from datetime import datetime
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from email import policy
from email.parser import BytesParser

app = Flask(__name__)
load_dotenv()

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'eml'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Get API key from environment
VT_API_KEY = os.getenv('VT_API_KEY')

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_email_content(filepath):
    """Extract content from .eml file"""
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            body = msg.get_body(preferencelist=('plain'))
            if body:
                return body.get_content()
            else:
                return ''
    except Exception as e:
        print(f"Error extracting email content: {e}")
        return ''

def extract_urls(text):
    """Extract URLs from email content"""
    url_pattern = re.compile(r'https?://\S+')
    urls = re.findall(url_pattern, text)
    return urls

def encode_url_for_vt(url):
    """Encode URL for VirusTotal API"""
    url_bytes = url.encode('utf-8')
    encoded = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')
    return encoded

def get_virustotal_analysis(url, api_key, max_retries=5, wait_time=12):
    """
    Get comprehensive VirusTotal analysis with actual scan results
    """
    headers = {'x-apikey': api_key}

    try:
        # First, check if URL already exists in VT database
        encoded_url = encode_url_for_vt(url)
        print(f"Checking existing analysis for: {url}")

        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{encoded_url}',
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            # URL exists, return existing analysis
            print(f"Found existing analysis for: {url}")
            return parse_vt_response(response.json(), url, "Existing Analysis")

        elif response.status_code == 404:
            # URL not in database, submit for analysis
            print(f"Submitting new URL for analysis: {url}")

            submit_response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=15
            )

            if submit_response.status_code != 200:
                return {
                    'url': url,
                    'status': 'Failed to submit',
                    'error': f'Submission failed with status {submit_response.status_code}',
                    'verdict': 'ERROR',
                    'threat_level': 'UNKNOWN'
                }

            # Get analysis ID from submission response
            analysis_id = submit_response.json()['data']['id']
            print(f"Analysis ID: {analysis_id}")

            # Wait for analysis to complete
            for attempt in range(max_retries):
                print(f"Waiting for analysis completion... attempt {attempt + 1}/{max_retries}")
                time.sleep(wait_time)  # Wait before checking

                analysis_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers=headers,
                    timeout=15
                )

                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    status = analysis_data['data']['attributes']['status']
                    print(f"Analysis status: {status}")

                    if status == 'completed':
                        # Analysis complete, get the URL report
                        print("Analysis completed, fetching results...")
                        time.sleep(2)  # Brief pause before fetching results

                        final_response = requests.get(
                            f'https://www.virustotal.com/api/v3/urls/{encoded_url}',
                            headers=headers,
                            timeout=15
                        )

                        if final_response.status_code == 200:
                            return parse_vt_response(final_response.json(), url, "New Analysis")
                        else:
                            return {
                                'url': url,
                                'status': 'Analysis completed but failed to retrieve results',
                                'analysis_id': analysis_id,
                                'verdict': 'ERROR',
                                'threat_level': 'UNKNOWN'
                            }
                    else:
                        # Still processing
                        if attempt == max_retries - 1:
                            return {
                                'url': url,
                                'status': 'Analysis timeout - still processing',
                                'analysis_id': analysis_id,
                                'note': 'Check again later with this analysis ID',
                                'verdict': 'PENDING',
                                'threat_level': 'ANALYZING'
                            }
                        continue
                else:
                    if attempt == max_retries - 1:
                        return {
                            'url': url,
                            'status': 'Failed to check analysis status',
                            'analysis_id': analysis_id,
                            'verdict': 'ERROR',
                            'threat_level': 'UNKNOWN'
                        }
        else:
            return {
                'url': url,
                'status': f'API Error: {response.status_code}',
                'error': response.text[:200],
                'verdict': 'ERROR',
                'threat_level': 'UNKNOWN'
            }

    except requests.RequestException as e:
        return {
            'url': url,
            'status': 'Network Error',
            'error': str(e),
            'verdict': 'ERROR',
            'threat_level': 'UNKNOWN'
        }

def parse_vt_response(vt_data, url, analysis_type):
    """
    Parse VirusTotal response and extract detailed information
    """
    try:
        attributes = vt_data['data']['attributes']
        stats = attributes['last_analysis_stats']
        scan_results = attributes.get('last_analysis_results', {})

        # Get scan details from individual engines
        engine_results = []
        malicious_engines = []
        suspicious_engines = []

        for engine_name, result in scan_results.items():
            engine_info = {
                'engine': engine_name,
                'category': result['category'],
                'result': result.get('result', 'clean')
            }
            engine_results.append(engine_info)

            if result['category'] == 'malicious':
                malicious_engines.append(engine_name)
            elif result['category'] == 'suspicious':
                suspicious_engines.append(engine_name)

        # Determine threat level
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        total_scans = sum(stats.values())

        if malicious_count > 0:
            threat_level = "HIGH RISK"
            verdict = "MALICIOUS"
        elif suspicious_count > 2:
            threat_level = "MEDIUM RISK"
            verdict = "SUSPICIOUS"
        elif suspicious_count > 0:
            threat_level = "LOW RISK"
            verdict = "POSSIBLY SUSPICIOUS"
        else:
            threat_level = "SAFE"
            verdict = "CLEAN"

        # Format scan date
        scan_timestamp = attributes.get('last_analysis_date')
        scan_date = datetime.fromtimestamp(scan_timestamp).strftime('%Y-%m-%d %H:%M:%S') if scan_timestamp else 'Unknown'

        return {
            'url': url,
            'analysis_type': analysis_type,
            'verdict': verdict,
            'threat_level': threat_level,
            'scan_date': scan_date,
            'status': f"{verdict} - {threat_level}",
            'statistics': {
                'malicious': malicious_count,
                'suspicious': suspicious_count,
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'timeout': stats.get('timeout', 0),
                'total_engines': total_scans
            },
            'detection_ratio': f"{malicious_count + suspicious_count}/{total_scans}",
            'malicious_engines': malicious_engines,
            'suspicious_engines': suspicious_engines,
            'all_engine_results': engine_results[:15],  # Show more engines
            'permalink': f"https://www.virustotal.com/gui/url/{encode_url_for_vt(url)}/detection"
        }

    except KeyError as e:
        return {
            'url': url,
            'status': 'Error parsing VirusTotal response',
            'error': f'Missing key: {str(e)}',
            'verdict': 'ERROR',
            'threat_level': 'UNKNOWN'
        }

def scan_urls_virustotal_enhanced(urls):
    """Enhanced VirusTotal scanning with full response analysis"""
    if not VT_API_KEY:
        return {'error': 'VirusTotal API key not configured'}

    print(f"Starting VirusTotal analysis for {len(urls)} URLs")
    results = []
    is_malicious = False

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] Analyzing URL: {url}")
        vt_result = get_virustotal_analysis(url, VT_API_KEY)

        # Check if this URL is malicious based on detailed analysis
        if vt_result.get('verdict') in ['MALICIOUS', 'SUSPICIOUS']:
            is_malicious = True

        results.append(vt_result)

        # Respect API rate limits (4 requests per minute for free tier)
        if i < len(urls):  # Don't wait after the last URL
            print("Waiting 16 seconds to respect API rate limits...")
            time.sleep(16)  # 16 seconds between requests for safety

    print(f"VirusTotal analysis completed. Malicious URLs found: {is_malicious}")
    return {'is_malicious': is_malicious, 'url_results': results}

def analyze_email_content(content):
    """Enhanced phishing detection based on common patterns"""
    suspicious_phrases = [
        'urgent action required',
        'verify your account',
        'click here immediately',
        'suspended account',
        'confirm your identity',
        'update payment information',
        'act now',
        'limited time offer',
        'congratulations you have won',
        'claim your prize',
        'account will be closed',
        'verify within 24 hours',
        'security alert',
        'unusual activity',
        'click to verify',
        'confirm now',
        'immediate attention required'
    ]

    content_lower = content.lower()
    detected_phrases = []

    for phrase in suspicious_phrases:
        if phrase in content_lower:
            detected_phrases.append(phrase)

    # Calculate suspicion score
    suspicion_score = len(detected_phrases)

    # Additional scoring based on content characteristics
    if re.search(r'\b(paypal|amazon|apple|microsoft|google|bank|credit)\b', content_lower):
        suspicion_score += 1

    if len(re.findall(r'https?://', content)) > 3:
        suspicion_score += 1

    return {
        'is_suspicious': len(detected_phrases) > 0,
        'detected_phrases': detected_phrases,
        'suspicion_score': suspicion_score,
        'total_phrases_checked': len(suspicious_phrases)
    }

def format_analysis_output(result):
    """
    Format the analysis result in the requested style
    """
    output = []

    # Header
    verdict = result.get('verdict', 'ANALYSIS COMPLETE')
    output.append(f"**{verdict}**")
    output.append(f"**Confidence:** {result.get('confidence', 'Medium')}")
    output.append("")

    # Reasons
    reasons = result.get('reasons', [])
    if reasons:
        output.append("**Reasons:**")
        for reason in reasons:
            output.append(f"* {reason}")
        output.append("")

    # URL Analysis
    url_results = result.get('url_analysis', [])
    if url_results:
        output.append(f"**URLs Found:** {len(url_results)}")
        output.append("")

        for url_result in url_results:
            output.append(f"**URL:** {url_result['url']}")
            output.append(f"**Status:** {url_result['status']}")

            if 'statistics' in url_result:
                output.append(f"**Detection Ratio:** {url_result.get('detection_ratio', 'N/A')}")
                output.append(f"**Threat Level:** {url_result.get('threat_level', 'Unknown')}")

                if url_result.get('malicious_engines'):
                    engines = ', '.join(url_result['malicious_engines'][:5])
                    output.append(f"**Malicious Detections:** {engines}")

                if url_result.get('suspicious_engines'):
                    engines = ', '.join(url_result['suspicious_engines'][:3])
                    output.append(f"**Suspicious Detections:** {engines}")

                output.append(f"**Scan Date:** {url_result.get('scan_date', 'N/A')}")
                output.append(f"**VirusTotal Link:** {url_result.get('permalink', 'N/A')}")

            output.append("")

    # Suspicious phrases
    content_analysis = result.get('content_analysis', {})
    if content_analysis.get('detected_phrases'):
        output.append("**Suspicious Phrases Detected:**")
        for phrase in content_analysis['detected_phrases']:
            output.append(f'* "{phrase}"')
        output.append("")

    # Summary
    output.append(f"**Analysis Summary:**")
    output.append(f"* URLs analyzed: {len(url_results)}")
    output.append(f"* Suspicious phrases found: {len(content_analysis.get('detected_phrases', []))}")
    output.append(f"* Overall risk level: {'HIGH' if result.get('is_phishing') else 'LOW'}")

    return "\n".join(output)

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """Main endpoint to analyze uploaded email file with enhanced VirusTotal integration"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Please upload a .eml file'}), 400

        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        print(f"Processing file: {filename}")

        # Extract email content
        email_content = extract_email_content(filepath)

        if not email_content:
            os.remove(filepath)
            return jsonify({'error': 'Could not extract content from email file'}), 400

        print(f"Extracted email content: {len(email_content)} characters")

        # Extract URLs
        urls = extract_urls(email_content)
        print(f"Found {len(urls)} URLs: {urls}")

        # Enhanced VirusTotal analysis
        vt_results = scan_urls_virustotal_enhanced(urls)

        # Analyze email content for suspicious patterns
        content_analysis = analyze_email_content(email_content)
        print(f"Content analysis: {content_analysis['suspicion_score']} suspicious elements found")

        # Determine final verdict
        is_phishing = vt_results.get('is_malicious', False) or content_analysis['is_suspicious']

        # Build reasons list
        reasons = []
        if vt_results.get('is_malicious'):
            malicious_urls = [r for r in vt_results.get('url_results', []) if r.get('verdict') in ['MALICIOUS', 'SUSPICIOUS']]
            if malicious_urls:
                reasons.append(f'Contains {len(malicious_urls)} malicious/suspicious URLs')

        if content_analysis['is_suspicious']:
            reasons.append(f'Contains suspicious phrases: {", ".join(content_analysis["detected_phrases"])}')

        if not reasons:
            reasons.append('No suspicious content detected')

        # Determine confidence level
        confidence_factors = 0
        if vt_results.get('is_malicious'):
            confidence_factors += 2
        if content_analysis['suspicion_score'] > 2:
            confidence_factors += 1
        if len(urls) > 0 and vt_results.get('is_malicious'):
            confidence_factors += 1

        confidence = 'High' if confidence_factors >= 2 else 'Medium' if confidence_factors == 1 else 'Low'

        # Build final result
        result = {
            'is_phishing': is_phishing,
            'verdict': 'PHISHING DETECTED' if is_phishing else 'EMAIL APPEARS SAFE',
            'confidence': confidence,
            'reasons': reasons,
            'url_analysis': vt_results.get('url_results', []),
            'urls_found': len(urls),
            'content_analysis': content_analysis,
            'processing_time': 'Analysis completed',
            'timestamp': datetime.now().isoformat()
        }

        # Generate formatted output
        formatted_output = format_analysis_output(result)
        result['formatted_output'] = formatted_output

        # Clean up uploaded file
        try:
            os.remove(filepath)
        except:
            pass

        print(f"Analysis completed. Phishing detected: {is_phishing}")
        return jsonify({'success': True, 'result': result})

    except Exception as e:
        print(f"Analysis error: {str(e)}")
        # Clean up file if it exists
        try:
            if 'filepath' in locals():
                os.remove(filepath)
        except:
            pass

        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/check-analysis/<analysis_id>', methods=['GET'])
def check_analysis_status(analysis_id):
    """Check the status of a VirusTotal analysis"""
    if not VT_API_KEY:
        return jsonify({'error': 'VirusTotal API key not configured'}), 400

    headers = {'x-apikey': VT_API_KEY}

    try:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'analysis_id': analysis_id,
                'status': data['data']['attributes']['status'],
                'stats': data['data']['attributes'].get('stats', {})
            })
        else:
            return jsonify({'error': f'Failed to check analysis: {response.status_code}'}), 400

    except Exception as e:
        return jsonify({'error': f'Error checking analysis: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Enhanced health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Enhanced Phishing Analyzer API is running',
        'vt_api_configured': bool(VT_API_KEY),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/test-vt', methods=['GET'])
def test_virustotal():
    """Test VirusTotal API connectivity"""
    if not VT_API_KEY:
        return jsonify({'error': 'VirusTotal API key not configured'}), 400

    headers = {'x-apikey': VT_API_KEY}

    try:
        # Test with a known URL
        response = requests.get(
            'https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ',  # google.com encoded
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            return jsonify({
                'success': True,
                'message': 'VirusTotal API is working correctly',
                'api_quota_remaining': response.headers.get('X-API-Quota-Remaining', 'Unknown')
            })
        else:
            return jsonify({
                'success': False,
                'error': f'VirusTotal API returned status: {response.status_code}',
                'message': 'Check your API key'
            }), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to connect to VirusTotal: {str(e)}'
        }), 500

def find_free_port():
    """Find a free port to run the Flask app"""
    for port in range(5001, 5010):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return 5001

if __name__ == '__main__':
    if not VT_API_KEY:
        print("WARNING: VT_API_KEY not found in environment variables!")
        print("Please create a .env file with your VirusTotal API key:")
        print("VT_API_KEY=your_api_key_here")

    port = find_free_port()
    print(f"🚀 Starting Enhanced Phishing Detection API on port {port}")
    print(f"📡 API endpoint: http://localhost:{port}/api/analyze")
    print(f"🏥 Health check: http://localhost:{port}/health")
    print(f"🧪 Test VirusTotal: http://localhost:{port}/api/test-vt")
    print(f"VirusTotal API configured: {'✅ Yes' if VT_API_KEY else '❌ No'}")

    app.run(debug=True, host='0.0.0.0', port=port)