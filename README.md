# Slush SDK

[![license](https://img.shields.io/github/license/tendermint/tendermint.svg)](https://github.com/slushsdk/slush/blob/master/LICENSE)



The Slush SDK allows you to spin up L3s on Starknet.

For now this entails running Tendermint nodes and linking them to light clients on Starknet. This repo contains the modified Tendermint files as well as the Cairo contracts (modelled on [Tendermint-Sol](https://github.com/ChorusOne/tendermint-sol)).

This first release focuses on communication between a single Tendermint node and the Starknet light client contract, meaning we have the following implemented:
- [x] Deploy Cairo light client contract to devnet, where Tendermint light headers can be verified
- [x] Run KV Store app on Tendermint as a demo

In the next release we will have the [multi node](https://docs.tendermint.com/v0.34/networks/docker-compose.html) support of Tendermint running.

Send transactions to tendermint with the [ABCI-CLI](https://docs.tendermint.com/v0.34/app-dev/abci-cli.html).


## Requirements

| Tool                                                                                 |  version                                                                       |
| -------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| [Go](https://go.dev/doc/install)                                                     |  [1.17](https://go.dev/doc/go1.17)                                             |
| [Cairo](https://www.cairo-lang.org/docs/quickstart.html)                             |  [0.10.3](https://github.com/starkware-libs/cairo-lang/releases/tag/v0.10.3)   |
| [Starknet Devnet](https://shard-labs.github.io/starknet-devnet/docs/intro#install)   |  [0.4.2](https://github.com/Shard-Labs/starknet-devnet/releases/tag/v0.4.2)    |
| Python (with [pyenv](https://github.com/pyenv/pyenv))                                |  [3.9](https://www.python.org/downloads/release/python-390/)                   |

Before installing Starknet Devnet on M1 check [this thread](https://github.com/OpenZeppelin/nile/issues/22).

## Quick Start


1. Clone this repo
2. Start the Starknet devnet. This will take up the view of Terminal
   - `starknet-devnet --seed=42`
3. Open a new terminal. Run the following at the root of this repo
   - `make build`
   - `./build/slush init validator --home ./valdata`
   - `./build/slush start --proxy-app=kvstore --home ./valdata`
4. If restarting this multiple times you might need to remove the validator data before `make build`:
   - `rm -r ./valdata/config/ ./valdata/data/`


## Local testnet with multiple nodes

The local testnet spins up the nodes in docker containers. Please make sure that docker desktop is installed and running ([docker desktop installation](https://www.docker.com/products/docker-desktop)).

Start Starknet devnet either locally on your machine or in docker:
>locally:
>```sh
>starknet-devnet
>```
>docker (linux/amd64):
>```sh
>docker run --rm -p 5050:5050 -d --name devnet shardlabs/starknet-devnet
>```
>docker (linux/arm64/v8):
>```sh
>docker run --rm -p 5050:5050 -d --name devnet shardlabs/starknet-devnet:latest-arm
>```

Create an account on devnet:
```sh
./create_devnet_account.sh
```

Build the linux binary:
```sh
make build-linux
```

Start the local testnet:
```sh
make localnet-start
```

Cleanup:
```sh
make clean && docker stop devnet
```

## Roadmap

Our roadmap is [here](https://geometry.xyz/notebook/the-road-to-slush).

## Join us!
We are looking for [exciting engineers](https://slush.dev/careers) to join!
