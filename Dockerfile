FROM python:3.10-slim

WORKDIR /app

# Install docker client (for load.py which uses docker exec) and curl (for healthcheck)
RUN apt-get update && \
    apt-get install -y --no-install-recommends docker.io curl && \
    rm -rf /var/lib/apt/lists/*

# Copy requirement files first for better caching
COPY requirement.txt ./
COPY fetcher_agent/requirements.txt ./fetcher_reqs.txt
COPY validation_agent/requirements.txt ./validation_reqs.txt

# Install python dependencies
RUN pip install --no-cache-dir -r requirement.txt -r fetcher_reqs.txt -r validation_reqs.txt

# Copy the rest of the application
COPY . .

# Make the pipeline script executable
RUN chmod +x run_pipeline.sh

CMD ["./run_pipeline.sh"]
