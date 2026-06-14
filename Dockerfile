FROM python:3.10-slim

WORKDIR /app

# Install curl and ca-certificates to download docker client
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz | tar -xz -C /tmp && \
    mv /tmp/docker/docker /usr/local/bin/ && \
    rm -rf /tmp/docker && \
    apt-get purge -y --auto-remove ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy requirement files first for better caching
COPY requirements.txt ./
COPY fetcher_agent/requirements.txt ./fetcher_reqs.txt
COPY validation_agent/requirements.txt ./validation_reqs.txt

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt -r fetcher_reqs.txt -r validation_reqs.txt

# Copy the rest of the application
COPY . .

# Make the pipeline script executable
RUN chmod +x run_pipeline.sh

CMD ["./run_pipeline.sh"]
