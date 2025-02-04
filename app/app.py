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
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

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
    prompt = f"""
    You are a Kubernetes expert. Analyze this Dockerfile and extract detailed configuration for Kubernetes manifests generation.
    Provide a comprehensive analysis in valid JSON format with these exact keys:

    Dockerfile to analyze:
    {dockerfile_content}

    Return the analysis in this exact JSON structure:
    {{
        "base_image": "exact base image with tag",
        "exposed_ports": [
            // List all exposed ports as integers
            // Example: [8080, 443]
        ],
        "environment_variables": {{
            // All ENV and ARG instructions as key-value pairs
            // Example: {{"NODE_ENV": "production", "PORT": "8080"}}
        }},
        "working_directory": "exact WORKDIR path",
        "entrypoint": [
            // ENTRYPOINT instructions as array
            // Example: ["node", "server.js"]
        ],
        "cmd": [
            // CMD instructions as array
            // Example: ["npm", "start"]
        ],
        "volumes": [
            // All VOLUME instructions as array of paths
            // Example: ["/app/data", "/app/logs"]
        ],
        "resources": {{
            "memory": "suggested memory limit based on application type",
            "cpu": "suggested cpu limit based on application type",
            "memory_request": "suggested memory request",
            "cpu_request": "suggested cpu request"
        }},
        "health_check": {{
            "type": "http or tcp based on application",
            "port": "port number",
            "path": "health check endpoint if http",
            "initial_delay": "seconds",
            "period": "seconds"
        }},
        "application_type": "web/backend/database/etc",
        "suggested_replicas": "number based on application type",
        "security_context": {{
            "run_as_non_root": true,
            "read_only_root_filesystem": true
        }}
    }}

    Important guidelines:
    1. Extract exact values from Dockerfile where present
    2. Make intelligent suggestions for missing values based on the application type
    3. For resources, suggest practical limits based on the application type:
       - Web apps: 256Mi-512Mi memory, 0.2-0.5 CPU
       - Backend services: 512Mi-1Gi memory, 0.5-1 CPU
       - Databases: 1Gi-2Gi memory, 1-2 CPU
    4. Include security best practices
    5. Suggest health checks based on application type
    6. Determine optimal replica count based on application type
    7. All numeric values should be integers, not strings
    8. Ensure the output is valid JSON

    Focus on production-ready configurations and Kubernetes best practices.
    """

    try:
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        
        # Clean the response text to ensure it's valid JSON
        cleaned_response = response.text.strip()
        if cleaned_response.startswith('```json'):
            cleaned_response = cleaned_response[7:-3]  # Remove ```json and ``` markers
        elif cleaned_response.startswith('```'):
            cleaned_response = cleaned_response[3:-3]  # Remove ``` markers
        
        analysis = json.loads(cleaned_response)
        print("Dockerfile Analysis:", analysis)  # Debug log
        return analysis
    except Exception as e:
        print(f"Error analyzing Dockerfile: {str(e)}")
        print("Raw response:", response.text)
        # Provide sensible defaults based on common web applications
        return {
            "base_image": "nginx:latest",
            "exposed_ports": [80],
            "environment_variables": {},
            "working_directory": "/app",
            "entrypoint": [],
            "cmd": [],
            "volumes": [],
            "resources": {
                "memory": "512Mi",
                "cpu": "0.5",
                "memory_request": "256Mi",
                "cpu_request": "0.2"
            },
            "health_check": {
                "type": "http",
                "port": 80,
                "path": "/health",
                "initial_delay": 30,
                "period": 10
            },
            "application_type": "web",
            "suggested_replicas": 2,
            "security_context": {
                "run_as_non_root": True,
                "read_only_root_filesystem": True
            }
        }

def generate_deployment_yaml(image_name, docker_analysis):
    """Generate Kubernetes Deployment YAML using Dockerfile analysis"""
    try:
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
                            'image': image_name,
                            'ports': [{'containerPort': port} for port in docker_analysis.get('exposed_ports', [80])],
                            'env': [{'name': k, 'value': str(v)} for k, v in docker_analysis.get('environment_variables', {}).items()],
                            'volumeMounts': [{'name': f'vol-{i}', 'mountPath': path} for i, path in enumerate(docker_analysis.get('volumes', []))],
                            'resources': docker_analysis.get('resources', {}),
                            'workingDir': docker_analysis.get('working_directory', '/app')
                        }]
                    }
                }
            }
        }
        return yaml.dump(deployment, default_flow_style=False)
    except Exception as e:
        print(f"Error generating deployment YAML: {str(e)}")
        return None

def generate_service_yaml(image_name, docker_analysis):
    """Generate Kubernetes Service YAML"""
    try:
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
                        'port': port,
                        'targetPort': port,
                        'protocol': 'TCP'
                    } for port in docker_analysis.get('exposed_ports', [80])
                ],
                'type': 'ClusterIP'
            }
        }
        return yaml.dump(service, default_flow_style=False)
    except Exception as e:
        print(f"Error generating service YAML: {str(e)}")
        return None

def generate_ingress_yaml(image_name, host_name):
    """Generate Kubernetes Ingress YAML"""
    try:
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
                                        'number': 80
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
        prompt = f"""
        Analyze this Dockerfile and provide detailed configuration information.
        Focus on extracting:
        1. Base image and version
        2. Exposed ports
        3. Environment variables
        4. Working directory
        5. Entry point or CMD
        6. Volume mounts
        7. Application type (web, backend, database, etc.)
        8. Resource requirements
        
        Dockerfile:
        {dockerfile_content}
        
        Provide the analysis in a structured JSON format.
        """
        
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        
        # Parse and validate the analysis
        analysis = parse_gemini_response(response.text)
        return jsonify(analysis)
        
    except Exception as e:
        print(f"Error analyzing Dockerfile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/generate-k8s-files', methods=['POST'])
def generate_k8s_files():
    try:
        if 'analysis' not in request.form:
            return jsonify({'error': 'No Dockerfile analysis provided'}), 400
        
        analysis = json.loads(request.form['analysis'])
        image_name = request.form.get('imageName', 'my-app')
        host_name = request.form.get('hostName', 'example.com')
        
        # Generate Kubernetes files using Gemini
        prompt = f"""
        Generate Kubernetes YAML files (Deployment, Service, and Ingress) based on this Dockerfile analysis:
        {json.dumps(analysis, indent=2)}
        
        Image Name: {image_name}
        Host Name: {host_name}
        
        Requirements:
        1. Follow Kubernetes best practices
        2. Include resource limits and requests
        3. Add appropriate health checks
        4. Configure security contexts
        5. Set up proper networking
        
        Provide three separate YAML files: deployment.yaml, service.yaml, and ingress.yaml
        """
        
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        
        # Parse the generated YAML files
        yamls = parse_kubernetes_yamls(response.text)
        
        return jsonify({
            'deployment': yamls.get('deployment', ''),
            'service': yamls.get('service', ''),
            'ingress': yamls.get('ingress', '')
        })
        
    except Exception as e:
        print(f"Error generating Kubernetes files: {str(e)}")
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