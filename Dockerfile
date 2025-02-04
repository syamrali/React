# Use a slim Python image
FROM python:3.9-slim

# Set working directory inside the container
WORKDIR /app

# Ensure pip is installed and updated
RUN python -m ensurepip && pip install --upgrade pip

# Copy dependencies first to leverage caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY app/ .

# Set environment variables for Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Expose port 8080
EXPOSE 8080

# Command to run the app
CMD ["python", "app.py"]
