from flask import Flask, render_template, request, jsonify
import google.generativeai as genai
from dotenv import load_dotenv
import os
import yaml
import json
import re

# Load environment variables and configure Gemini
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    raise ValueError("Please set your Google Gemini API key in .env file")

genai.configure(api_key=GEMINI_API_KEY)

app = Flask(__name__)

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

def analyze_dockerfile(file_content):
    """
    Analyze Dockerfile content using Gemini AI.
    """
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"""
        Analyze the following Dockerfile and extract configuration details in JSON format:
        {file_content}
        
        Return a JSON object with these fields:
        - base_image: The base image used
        - ports: List of exposed ports
        - env_vars: List of environment variables
        - volumes: List of volumes
        - command: Default command or entrypoint
        - resources: Any resource specifications found
        """
        response = model.generate_content(prompt)
        
        # Try to extract JSON from the response
        try:
            json_match = re.search(r'```json\n(.*?)\n```', response.text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            return json.loads(response.text)
        except json.JSONDecodeError:
            return {}
    except Exception as e:
        return {"error": str(e)}

def generate_deployment_yaml(image_name, dockerfile_config=None, gemini_suggestions=None):
    """
    Generate a Kubernetes deployment file.
    """
    if dockerfile_config is None:
        dockerfile_config = {}
    
    ports = dockerfile_config.get('ports', [80])
    env_vars = dockerfile_config.get('env_vars', [])
    
    deployment = {
        'apiVersion': 'apps/v1',
        'kind': 'Deployment',
        'metadata': {
            'name': f'{image_name}-deployment'
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
                        'ports': [{'containerPort': port} for port in ports]
                    }]
                }
            }
        }
    }
    
    return yaml.dump(deployment)

def generate_service_yaml(image_name, dockerfile_config=None):
    """
    Generate a Kubernetes service file.
    """
    if dockerfile_config is None:
        dockerfile_config = {}
    
    ports = dockerfile_config.get('ports', [80])
    
    service = {
        'apiVersion': 'v1',
        'kind': 'Service',
        'metadata': {
            'name': f'{image_name}-service'
        },
        'spec': {
            'selector': {
                'app': image_name
            },
            'ports': [{
                'protocol': 'TCP',
                'port': port,
                'targetPort': port
            } for port in ports],
            'type': 'ClusterIP'
        }
    }
    
    return yaml.dump(service)

def generate_ingress_yaml(image_name, host_name):
    """
    Generate a Kubernetes ingress file.
    """
    ingress = {
        'apiVersion': 'networking.k8s.io/v1',
        'kind': 'Ingress',
        'metadata': {
            'name': f'{image_name}-ingress'
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
                                'name': f'{image_name}-service',
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
    
    return yaml.dump(ingress)

@app.route('/')
def index():
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

@app.route('/generate-kubernetes', methods=['POST'])
def generate_kubernetes():
    if 'dockerfile' not in request.files:
        return jsonify({'error': 'No Dockerfile uploaded'}), 400
    
    dockerfile = request.files['dockerfile']
    image_name = request.form.get('image_name', 'my-app')
    host_name = request.form.get('host_name', 'example.com')
    
    dockerfile_content = dockerfile.read().decode('utf-8')
    dockerfile_config = analyze_dockerfile(dockerfile_content)
    
    deployment_yaml = generate_deployment_yaml(image_name, dockerfile_config)
    service_yaml = generate_service_yaml(image_name, dockerfile_config)
    ingress_yaml = generate_ingress_yaml(image_name, host_name)
    
    return jsonify({
        'deployment': deployment_yaml,
        'service': service_yaml,
        'ingress': ingress_yaml
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)