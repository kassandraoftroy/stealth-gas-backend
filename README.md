# Stealth Gas Backend

a backend that listens to and fulfills stealth gas ticket requests using [this smart contract](https://github.com/kassandraoftroy/stealth-gas-contracts)

eventually it will deploy and run inside a TEE (trusted execution environment)

## Setup

```
touch .env
```

you need to fill out .env file (see .env.example)

```
docker-compose build
```

```
docker-compose up -d db
```

```
chmod +x scripts/setup.sh
```

```
scripts/setup.sh
```

```
docker-compose up
```

## Tear down

```
docker-compose down
```

```
docker system prune -af
```