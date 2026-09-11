FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/

# Install the package
RUN pip install --no-cache-dir -e .

# Create a non-root user for security
RUN useradd -m -u 1000 megasast && \
    chown -R megasast:megasast /app

USER megasast

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose port (if needed for web interface)
EXPOSE 8080

# Command to run the CLI
CMD ["megasast"]
