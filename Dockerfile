# Stage 1: Build the Rust app
FROM rust:latest AS builder

WORKDIR /app

# Copy project files, excluding those in .dockerignore
COPY . .

# Install dependencies and build the project in release mode
RUN cargo build --release

# Stage 2: Create a lightweight image to run the app
FROM ubuntu:22.04

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/eth_stealth_gas_tickets /app/eth_stealth_gas_tickets

# Copy the .env file
COPY .env /app/.env

# Expose port 8000 for the HTTP server
EXPOSE 8000

# Command to run the app
CMD ["./eth_stealth_gas_tickets"]
