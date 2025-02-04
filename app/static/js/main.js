document.addEventListener('DOMContentLoaded', function() {
  // AI-DevOps Guardian Form
  const guardianForm = document.getElementById('guardianForm');
  const guardianResult = document.getElementById('guardianResult');

  guardianForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      const file = document.getElementById('configFile').files[0];
      if (!file) return;

      const formData = new FormData();
      formData.append('file', file);

      try {
          const response = await fetch('/analyze', {
              method: 'POST',
              body: formData
          });
          const data = await response.json();
          
          guardianResult.classList.remove('hidden');
          guardianResult.querySelector('pre').textContent = data.result;
      } catch (error) {
          console.error('Error:', error);
      }
  });

  // Kubernetes YAML Generator Form
  const k8sForm = document.getElementById('k8sForm');
  const k8sResult = document.getElementById('k8sResult');

  k8sForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      const file = document.getElementById('dockerFile').files[0];
      const imageName = document.getElementById('imageName').value;
      const hostName = document.getElementById('hostName').value;

      if (!file || !imageName || !hostName) return;

      const formData = new FormData();
      formData.append('dockerfile', file);
      formData.append('image_name', imageName);
      formData.append('host_name', hostName);

      try {
          const response = await fetch('/generate-kubernetes', {
              method: 'POST',
              body: formData
          });
          const data = await response.json();
          
          k8sResult.classList.remove('hidden');
          const pres = k8sResult.querySelectorAll('pre');
          pres[0].textContent = data.deployment;
          pres[1].textContent = data.service;
          pres[2].textContent = data.ingress;
      } catch (error) {
          console.error('Error:', error);
      }
  });

  // Download YAML files
  document.querySelectorAll('.download-yaml').forEach(button => {
      button.addEventListener('click', function() {
          const type = this.dataset.type;
          const content = this.previousElementSibling.textContent;
          const blob = new Blob([content], { type: 'text/yaml' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${type}.yaml`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
      });
  });
});