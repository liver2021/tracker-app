# Use official Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements first and install dependencies
COPY requirements.txt .
# *** INSERT THE apt-get COMMAND HERE ***
RUN apt-get update && apt-get install -y python3-pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy rest of the application
COPY . .

# Expose port Elastic Beanstalk expects
EXPOSE 5000

# Run Flask application via Gunicorn (EB-friendly)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "application:application"]