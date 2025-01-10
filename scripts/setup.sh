#!/bin/bash
set -e

# Configuration
# Load environment variables from .env file
if [ -f .env ]; then
    source .env
else
    echo ".env file not found"
    exit 1
fi

NETWORK_NAME="stealth_gas_net"
DB_CONTAINER_NAME="stealth_gas_db"
POSTGRES_IMAGE="postgres:15"
# Use values from .env, with defaults if not set
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-postgres}" 
POSTGRES_DB="${POSTGRES_DB:-stealth-gas-backend}"
RUST_IMAGE="rust:latest"

# Step 1: Create Docker network if it doesn't exist
if ! docker network ls | grep -q $NETWORK_NAME; then
  echo "Creating Docker network: $NETWORK_NAME"
  docker network create $NETWORK_NAME
else
  echo "Docker network $NETWORK_NAME already exists."
fi

# Step 2: Start the PostgreSQL container if it's not already running
if ! docker ps | grep -q $DB_CONTAINER_NAME; then
  echo "Starting PostgreSQL container..."
  docker run --name $DB_CONTAINER_NAME -d \
    --network=$NETWORK_NAME \
    -e POSTGRES_USER=$POSTGRES_USER \
    -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
    -e POSTGRES_DB=$POSTGRES_DB \
    -p 5432:5432 $POSTGRES_IMAGE
else
  echo "PostgreSQL container is already running."
fi

# Step 3: Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
until docker exec $DB_CONTAINER_NAME pg_isready -U $POSTGRES_USER; do
  sleep 1
done
echo "PostgreSQL is ready!"

# Step 4: Run the Rust container to apply migrations
echo "Running migrations..."
docker run --rm \
  --network=$NETWORK_NAME \
  -e DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@$DB_CONTAINER_NAME:5432/$POSTGRES_DB" \
  -v "$(pwd)":/app \
  -w /app \
  $RUST_IMAGE bash -c "cargo install sqlx-cli && sqlx migrate run"

echo "Migrations applied successfully!"
echo "Database URL = postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@$DB_CONTAINER_NAME:5432/$POSTGRES_DB"
