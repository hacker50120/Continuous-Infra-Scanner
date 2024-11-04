# Use the official Python Alpine image
FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory
WORKDIR /usr/src/app

# Install dependencies
COPY requirements.txt ./
RUN apk update && \
    apk add --no-cache \
    build-base \
    libffi-dev \
    openssl-dev \
    nmap \
    nodejs \
    npm \
    postgresql-dev \
    musl-dev \
    gcc \
    python3-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    npm install -g pm2

# Copy the application code
COPY . .

# Expose the port the app runs on
EXPOSE 8180

# Run the application
CMD ["pm2-runtime", "pm2.config.js"]

