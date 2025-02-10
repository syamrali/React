from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import google.generativeai as genai
from dotenv import load_dotenv
import os
import yaml
import json
import re
from werkzeug.utils import secure_filename

# Load environment variables and configure Gemini
load_dotenv()
GEMINI_API_KEY = "AIzaSyBPnmeDYppp5cNfS9K9Ri-EoMiaxt78hCw"

if not GEMINI_API_KEY:
    raise ValueError("Please set your Google Gemini API key in .env file")

genai.configure(api_key=GEMINI_API_KEY)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # for session management

def analyze_with_gemini(file_content):
    """
    Analyze the given DevOps configuration file for misconfigurations
    and provide remediation suggestions using Google Gemini.
    """
    try:
        prompt = f"""
        You are an AI DevOps assistant. Analyze the following configuration file for misconfigurations, 
        vulnerabilities, and best practice violations. Provide a detailed report of issues and actionable remediation steps.

        Configuration File:
        {file_content}
        """
        model = genai.GenerativeModel("gemini-1.5-flash")
        result = model.generate_content([prompt])
        return result.text
    except Exception as e:
        return {"error": str(e)}

def analyze_dockerfile_with_gemini(dockerfile_content):
    try:
        prompt = f"""
        You are a Kubernetes expert. Analyze this Dockerfile and extract detailed configuration for Kubernetes manifests generation.
        Follow these guidelines strictly and be specific:

        1. Port Analysis (CRITICAL):
           - ONLY extract ports that are explicitly defined in EXPOSE directives
           - Do NOT add any default or assumed ports
           - If no EXPOSE directive exists, leave the ports list empty

        2. Base Image Analysis:
           - Identify the exact base image and version
           - Determine if it's an official image
           - Check if it runs as root or non-root by default

        3. Security Context Analysis:
           - Determine if the image requires root access
           - Check if the application writes to filesystem
           - Analyze USER directives
           - Check for any volume mounts that require write access
           - Identify any privileged operations

        4. Resource Requirements:
           - Base recommendations on the application type
           - Consider base image requirements
           - Adjust for any heavy dependencies or operations

        Dockerfile to analyze:
        {dockerfile_content}

        Return ONLY a JSON object with these exact keys and format:
        {{
            "base_image": {{
                "name": "full image name with tag",
                "is_official": true/false,
                "default_user": "root or non-root"
            }},
            "exposed_ports": [
                ONLY ports from EXPOSE directives, empty list if none found
            ],
            "security_context": {{
                "runAsNonRoot": true/false (based on actual analysis),
                "readOnlyRootFilesystem": true/false (based on write operations),
                "runAsUser": number (extracted from USER directive or default),
                "runAsGroup": number (extracted from USER directive or default),
                "allowPrivilegeEscalation": false,
                "capabilities": {{
                    "drop": ["ALL"],
                    "add": [list of required capabilities]
                }}
            }},
            "resources": {{
                "requests": {{
                    "memory": "memory size with unit",
                    "cpu": "cpu units as decimal"
                }},
                "limits": {{
                    "memory": "memory size with unit",
                    "cpu": "cpu units as decimal"
                }}
            }},
            "health_check": {{
                "type": "http or tcp based on actual application type",
                "port": port number from exposed ports only,
                "path": "/health or appropriate health endpoint",
                "initial_delay": seconds based on application startup time,
                "period": appropriate check interval
            }}
        }}

        Important:
        1. ONLY include ports that are explicitly defined in EXPOSE directives
        2. Do NOT add any assumed or default ports
        3. Base all decisions on actual Dockerfile content
        4. Be specific and accurate with all values
        """

        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        
        if not response or not response.text:
            print("Empty response from Gemini API")
            return get_default_analysis()
        
        # Clean the response text to ensure it's valid JSON
        cleaned_response = response.text.strip()
        if cleaned_response.startswith('```json'):
            cleaned_response = cleaned_response[7:-3]  # Remove ```json and ``` markers
        elif cleaned_response.startswith('```'):
            cleaned_response = cleaned_response[3:-3]  # Remove ``` markers
        
        try:
            analysis = json.loads(cleaned_response)
            # Validate and fix the analysis
            analysis = validate_and_fix_analysis(analysis)
            print("Dockerfile Analysis:", analysis)  # Debug log
            return analysis
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {str(e)}")
            print("Raw response:", cleaned_response)
            return get_default_analysis()
            
    except Exception as e:
        print(f"Error analyzing Dockerfile: {str(e)}")
        return get_default_analysis()

def get_default_analysis():
    """Return default analysis when Dockerfile analysis fails"""
    return {
        "base_image": {
            "name": "nginx:latest",
            "is_official": True,
            "default_user": "root"
        },
        "exposed_ports": [],  # Empty by default, will only be populated from EXPOSE directives
        "environment_variables": {},
        "working_directory": "/app",
        "entrypoint": [],
        "cmd": [],
        "volumes": [],
        "resources": {
            "requests": {
                "memory": "256Mi",
                "cpu": "0.2"
            },
            "limits": {
                "memory": "512Mi",
                "cpu": "0.5"
            }
        },
        "health_check": {
            "type": "http",
            "port": None,  # Will be set to first exposed port if available
            "path": "/health",
            "initial_delay": 30,
            "period": 10
        },
        "security_context": {
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "allowPrivilegeEscalation": False,
            "capabilities": {
                "drop": ["ALL"],
                "add": []
            }
        }
    }

def validate_and_fix_analysis(analysis):
    """Validate and fix the analysis data structure"""
    default_analysis = get_default_analysis()
    
    # Ensure all required fields exist
    for key in default_analysis.keys():
        if key not in analysis:
            analysis[key] = default_analysis[key]
    
    # Enhanced port handling - only use ports from Dockerfile EXPOSE
    if 'base_image' in analysis and isinstance(analysis['base_image'], dict):
        exposed_ports = analysis.get('exposed_ports', [])
        # Don't default to port 80, use empty list if no ports exposed
        analysis['exposed_ports'] = sorted(list(set(exposed_ports))) if exposed_ports else []
    
    # Enhanced security context handling
    if 'security_context' not in analysis or not isinstance(analysis['security_context'], dict):
        analysis['security_context'] = {
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "allowPrivilegeEscalation": False,
            "capabilities": {
                "drop": ["ALL"],
                "add": []
            }
        }
    else:
        security_context = analysis['security_context']
        # Ensure all security context fields exist with proper types
        analysis['security_context'] = {
            "runAsNonRoot": bool(security_context.get('runAsNonRoot', True)),
            "readOnlyRootFilesystem": bool(security_context.get('readOnlyRootFilesystem', True)),
            "runAsUser": int(security_context.get('runAsUser', 1000)),
            "runAsGroup": int(security_context.get('runAsGroup', 1000)),
            "allowPrivilegeEscalation": bool(security_context.get('allowPrivilegeEscalation', False)),
            "capabilities": {
                "drop": security_context.get('capabilities', {}).get('drop', ["ALL"]),
                "add": security_context.get('capabilities', {}).get('add', [])
            }
        }
    
    return analysis

def generate_deployment_yaml(full_image_name, image_name, docker_analysis):
    """Generate Kubernetes Deployment YAML"""
    try:
        print(f"Generating deployment YAML with analysis:", docker_analysis)
        print(f"Using full image name: {full_image_name}")
        
        # Format resources properly with requests and limits
        resources = {
            'requests': {
                'memory': docker_analysis.get('resources', {}).get('requests', {}).get('memory', '256Mi'),
                'cpu': docker_analysis.get('resources', {}).get('requests', {}).get('cpu', '0.2')
            },
            'limits': {
                'memory': docker_analysis.get('resources', {}).get('limits', {}).get('memory', '512Mi'),
                'cpu': docker_analysis.get('resources', {}).get('limits', {}).get('cpu', '0.5')
            }
        }
        
        # Only include ports if they were explicitly exposed
        # Convert ports to integers
        exposed_ports = docker_analysis.get('exposed_ports', [])
        container_ports = []
        if exposed_ports:
            container_ports = [{'containerPort': int(port)} for port in exposed_ports]  # Convert to int
        
        deployment = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': image_name
            },
            'spec': {
                'replicas': 1,
                'selector': {
                    'matchLabels': {
                        'app': image_name
                    }
                },
                'template': {
                    'metadata': {
                        'labels': {
                            'app': image_name
                        }
                    },
                    'spec': {
                        'containers': [{
                            'name': image_name,
                            'image': full_image_name,
                            'imagePullPolicy': 'Always',
                            'ports': container_ports,
                            'resources': resources
                        }]
                    }
                }
            }
        }
        
        # Add security context if specified
        security_context = docker_analysis.get('security_context', {})
        if security_context:
            deployment['spec']['template']['spec']['containers'][0]['securityContext'] = {
                'runAsNonRoot': bool(security_context.get('runAsNonRoot', True)),
                'readOnlyRootFilesystem': bool(security_context.get('readOnlyRootFilesystem', True)),
                'runAsUser': int(security_context.get('runAsUser', 1000)),
                'runAsGroup': int(security_context.get('runAsGroup', 1000)),
                'allowPrivilegeEscalation': bool(security_context.get('allowPrivilegeEscalation', False))
            }
            
            if 'capabilities' in security_context:
                deployment['spec']['template']['spec']['containers'][0]['securityContext']['capabilities'] = {
                    'drop': security_context.get('capabilities', {}).get('drop', ["ALL"]),
                    'add': security_context.get('capabilities', {}).get('add', [])
                }
        
        # Add health check if specified
        health_check = docker_analysis.get('health_check', {})
        if health_check:
            probe = {
                'initialDelaySeconds': int(health_check.get('initial_delay', 30)),
                'periodSeconds': int(health_check.get('period', 10))
            }
            
            if health_check.get('type') == 'http':
                probe['httpGet'] = {
                    'path': str(health_check.get('path', '/health')),
                    'port': int(health_check.get('port', 80))
                }
            elif health_check.get('type') == 'tcp':
                probe['tcpSocket'] = {
                    'port': int(health_check.get('port', 80))
                }
            
            deployment['spec']['template']['spec']['containers'][0]['livenessProbe'] = probe
            deployment['spec']['template']['spec']['containers'][0]['readinessProbe'] = probe
        
        return yaml.dump(deployment, default_flow_style=False)
    except Exception as e:
        print(f"Error generating deployment YAML: {str(e)}")
        return None

def generate_service_yaml(image_name, docker_analysis):
    """Generate Kubernetes Service YAML"""
    try:
        # Get exposed ports from analysis
        exposed_ports = docker_analysis.get('exposed_ports', [])
        
        # If no ports are exposed, don't create a service
        if not exposed_ports:
            print("No ports exposed in Dockerfile, skipping service generation")
            return None
            
        service = {
            'apiVersion': 'v1',
            'kind': 'Service',
            'metadata': {
                'name': image_name
            },
            'spec': {
                'selector': {
                    'app': image_name
                },
                'ports': [
                    {
                        'port': int(port),  # Convert to int
                        'targetPort': int(port),  # Convert to int
                        'protocol': 'TCP'
                    } for port in exposed_ports
                ],
                'type': 'ClusterIP'
            }
        }
        return yaml.dump(service, default_flow_style=False)
    except Exception as e:
        print(f"Error generating service YAML: {str(e)}")
        return None

def generate_ingress_yaml(image_name, host_name, docker_analysis):
    """Generate Kubernetes Ingress YAML"""
    try:
        # Get the first exposed port from analysis, default to 80 only if no ports are exposed
        exposed_ports = docker_analysis.get('exposed_ports', [])
        service_port = int(exposed_ports[0]) if exposed_ports else 80  # Convert to int
        
        ingress = {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'Ingress',
            'metadata': {
                'name': f"{image_name}-ingress",
                'annotations': {
                    'nginx.ingress.kubernetes.io/rewrite-target': '/'
                }
            },
            'spec': {
                'rules': [{
                    'host': host_name,
                    'http': {
                        'paths': [{
                            'path': '/',
                            'pathType': 'Prefix',
                            'backend': {
                                'service': {
                                    'name': image_name,
                                    'port': {
                                        'number': service_port  # Already converted to int
                                    }
                                }
                            }
                        }]
                    }
                }]
            }
        }
        return yaml.dump(ingress, default_flow_style=False)
    except Exception as e:
        print(f"Error generating ingress YAML: {str(e)}")
        return None

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    file_content = file.read().decode('utf-8')
    analysis_result = analyze_with_gemini(file_content)
    
    return jsonify({'result': analysis_result})

@app.route('/analyze-dockerfile', methods=['POST'])
def analyze_dockerfile():
    try:
        if 'dockerfile' not in request.files:
            return jsonify({'error': 'No Dockerfile uploaded'}), 400
        
        dockerfile = request.files['dockerfile']
        dockerfile_content = dockerfile.read().decode('utf-8')
        
        # Validate if it's a proper Dockerfile
        if not is_valid_dockerfile(dockerfile_content):
            return jsonify({'error': 'Invalid Dockerfile'}), 400
        
        # Analyze Dockerfile using Gemini
        analysis = analyze_dockerfile_with_gemini(dockerfile_content)
        return jsonify(analysis)
        
    except Exception as e:
        print(f"Error analyzing Dockerfile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/generate-k8s-files', methods=['POST'])
def generate_k8s_files():
    try:
        if 'dockerfile' not in request.files:
            return jsonify({'error': 'No Dockerfile uploaded'}), 400
        
        dockerfile = request.files['dockerfile']
        if not dockerfile.filename:
            return jsonify({'error': 'No Dockerfile selected'}), 400
        
        dockerfile_content = dockerfile.read().decode('utf-8')
        if not is_valid_dockerfile(dockerfile_content):
            return jsonify({'error': 'Invalid Dockerfile content'}), 400
        
        # Get analysis from Gemini
        analysis = analyze_dockerfile_with_gemini(dockerfile_content)
        if not analysis:
            return jsonify({'error': 'Failed to analyze Dockerfile'}), 500
        
        # Get form data with defaults
        docker_username = request.form.get('dockerUsername', '').strip()
        image_name = request.form.get('imageName', 'flaskapp-web').strip()
        image_tag = request.form.get('imageTag', 'latest').strip()
        host_name = request.form.get('hostName', 'example.com').strip()
        
        # Construct full image name
        full_image_name = f"{docker_username}/{image_name}:{image_tag}" if docker_username else f"{image_name}:{image_tag}"
        
        # Generate Kubernetes YAML files
        deployment_yaml = generate_deployment_yaml(full_image_name, image_name, analysis)
        if not deployment_yaml:
            return jsonify({'error': 'Failed to generate deployment YAML'}), 500
            
        service_yaml = generate_service_yaml(image_name, analysis)
        # Only return error if service generation fails but ports were exposed
        if service_yaml is None and analysis.get('exposed_ports'):
            return jsonify({'error': 'Failed to generate service YAML'}), 500
            
        ingress_yaml = generate_ingress_yaml(image_name, host_name, analysis)  # Pass analysis here
        if not ingress_yaml:
            return jsonify({'error': 'Failed to generate ingress YAML'}), 500
        
        response_data = {
            'deployment': deployment_yaml,
            'service': service_yaml if service_yaml else '',  # Return empty string if no service
            'ingress': ingress_yaml
        }
        
        print("Generated Kubernetes files successfully")
        print("Analysis used:", analysis)  # Debug log
        print("Exposed ports:", analysis.get('exposed_ports', []))  # Debug log
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Error in generate_k8s_files: {str(e)}")
        return jsonify({'error': str(e)}), 500

def is_valid_dockerfile(content):
    """Validate if the content is a proper Dockerfile"""
    required_instructions = ['FROM']
    content_upper = content.upper()
    return any(instruction in content_upper for instruction in required_instructions)

def parse_gemini_response(response_text):
    """Parse and clean Gemini's response"""
    try:
        # Remove markdown code blocks if present
        cleaned_text = response_text.strip()
        if cleaned_text.startswith('```'):
            cleaned_text = cleaned_text.split('```')[1]
            if cleaned_text.startswith('json'):
                cleaned_text = cleaned_text[4:]
        
        # Parse JSON
        return json.loads(cleaned_text)
    except Exception as e:
        print(f"Error parsing Gemini response: {str(e)}")
        return {
            'base_image': 'nginx:latest',
            'exposed_ports': [80],
            'environment_variables': {},
            'working_directory': '/app',
            'application_type': 'web',
            'resources': {
                'memory': '512Mi',
                'cpu': '0.5'
            }
        }

def parse_kubernetes_yamls(response_text):
    """Parse the generated Kubernetes YAML files from Gemini's response"""
    try:
        yamls = {}
        current_file = None
        current_content = []
        
        # Split response into lines
        lines = response_text.split('\n')
        for line in lines:
            if 'deployment.yaml' in line.lower():
                current_file = 'deployment'
                current_content = []
            elif 'service.yaml' in line.lower():
                if current_file and current_content:
                    yamls[current_file] = '\n'.join(current_content)
                current_file = 'service'
                current_content = []
            elif 'ingress.yaml' in line.lower():
                if current_file and current_content:
                    yamls[current_file] = '\n'.join(current_content)
                current_file = 'ingress'
                current_content = []
            elif line.strip() and current_file:
                current_content.append(line)
        
        if current_file and current_content:
            yamls[current_file] = '\n'.join(current_content)
        
        return yamls
    except Exception as e:
        print(f"Error parsing Kubernetes YAMLs: {str(e)}")
        return {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Add your authentication logic here
        # For demo purposes:
        if email == "demo@example.com" and password == "demo123":
            session['user'] = email
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')  # Create this template if needed

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)