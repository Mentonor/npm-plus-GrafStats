# Stage 1: Build environment
FROM python:3.14-slim AS builder

LABEL maintainer="npmgrafstats@smilebasti.de"

# Setup home folder
RUN mkdir -p /home/appuser/.config/NPMGRAF

# Install necessary packages for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc git build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements.txt /home/appuser/.config/NPMGRAF/requirements.txt
RUN pip install --no-cache-dir -r /home/appuser/.config/NPMGRAF/requirements.txt

# Stage 2: Runtime environment
FROM python:3.14-slim

# Setup home folder
RUN mkdir -p /home/appuser/.config/NPMGRAF

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser

# Create /data directory and set ownership to appuser
RUN mkdir -p /data && chown -R appuser:appuser /data

# Copy installed Python packages from the builder stage
COPY --from=builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages

# Copy Python scripts and set permissions
COPY log_processor.py /home/appuser/.config/NPMGRAF/log_processor.py
COPY start.sh /home/appuser/start.sh

RUN chmod +x /home/appuser/.config/NPMGRAF/log_processor.py /home/appuser/start.sh

# Change ownership to non-root user
RUN chown -R appuser:appuser /home/appuser/.config/NPMGRAF /home/appuser/start.sh

# Switch to non-root user
USER appuser

# Set the entry point
ENTRYPOINT ["/home/appuser/start.sh"]
