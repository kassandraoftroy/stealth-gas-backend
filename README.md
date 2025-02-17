# Stealth Gas Backend

a backend that listens to and fulfills stealth gas ticket requests using [this smart contract](https://github.com/kassandraoftroy/stealth-gas-contracts)

eventually it will deploy and run inside a TEE (trusted execution environment)

## Setup

```
touch .env
```

you need to fill out .env file (see .env.example)

```
sudo docker-compose build
```

```
sudo docker-compose up -d db
```

```
chmod +x scripts/setup.sh
```

```
scripts/setup.sh
```

```
sudo docker-compose up
```

## Tear down

```
sudo docker-compose down
```

```
sudo docker system prune -af
```