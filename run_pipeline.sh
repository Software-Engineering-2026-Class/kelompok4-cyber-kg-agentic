#!/bin/bash
set -e

echo "========================================"
echo "Starting CSKG Pipeline"
echo "========================================"

echo "1. Running Fetcher Agent..."
python fetcher_agent/main.py

echo "2. Running Parser Agent..."
python parser_agent/main.py

echo "3. Running Linking Agent..."
python linking_agent/main.py

echo "4. Running Validation Agent..."
python validation_agent/main.py

echo "5. Copying TTL files to toload directory..."
mkdir -p sparql_endpoint/toload
# find all ttl files except those in venv or already in toload, and copy them
find . -name "*.ttl" -not -path "*/venv/*" -not -path "*/sparql_endpoint/toload/*" -exec cp {} sparql_endpoint/toload/ \;

echo "6. Loading data into SPARQL Endpoint..."
# Wait for Virtuoso to be ready by pinging port 8890
echo "Waiting for Virtuoso to be ready on $VIRTUOSO_HOST:8890..."
until curl -s http://$VIRTUOSO_HOST:8890 > /dev/null; do
  echo "Virtuoso not ready yet, sleeping 5 seconds..."
  sleep 5
done

# Give Virtuoso a little extra time to fully initialize ISQL port 1111
echo "Virtuoso HTTP is up. Waiting 10s for ISQL port to settle..."
sleep 10

python sparql_endpoint/load.py

echo "========================================"
echo "CSKG Pipeline completed successfully!"
echo "========================================"

# Keep container alive so it doesn't immediately exit when using docker compose up
tail -f /dev/null
