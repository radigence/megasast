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
    mkdir -p /output && \
    chown -R megasast:megasast /app /output

USER megasast

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default scan target: mounted read-only at /scan-target, SARIF written to
# the writable /output mount. Any arguments appended to `docker run` follow
# this command, so `docker run megasast scan .` still works.
# This is a CLI scanner: no ports are exposed.
CMD ["megasast", "scan", "/scan-target", "-o", "/output/results.sarif", "--format", "sarif"]
