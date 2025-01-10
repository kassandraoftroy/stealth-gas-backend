#!/bin/bash
set -e

# Step 1: Load environment variables from .env
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Step 2: Bring up the database service
docker-compose up -d db

# Step 3: Wait for the database to be ready
echo "Waiting for PostgreSQL to be ready..."
until docker-compose exec db pg_isready -U "$POSTGRES_USER"; do
  sleep 1
done

# Step 4: Run migrations in a temporary Rust container with the project folder mounted
echo "Installing Rust and running migrations..."
docker run --rm \
  --network "${POSTGRES_DB}_stealth_gas_net" \
  -v "$(pwd):/app" \
  -w /app \
  -e DATABASE_URL="$DATABASE_URL" \
  rust:latest bash -c "
    cargo install sqlx-cli && \
    sqlx migrate run
  "

echo "Migrations complete!"
