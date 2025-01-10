# Stealth Gas Backend

a backend that listens to and fulfills stealth gas ticket requests using [this smart contract](https://github.com/kassandraoftroy/stealth-gas-contracts)

eventually it will deploy and run inside a TEE (trusted execution environment)

## Setup

```
touch .env
```
you need to fill out .env file (see .env.example) you'll do DATABASE_URL at the end

```
chmod +x scripts/setup.sh
```

```
./scripts/setup.sh
```

fill in DATABASE_URL in .env and docker-compose.yml

```
docker build -t stealth_gas_app .
```

```
docker-compose up
```

