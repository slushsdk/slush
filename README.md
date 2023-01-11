# Slush SDK

[![license](https://img.shields.io/github/license/tendermint/tendermint.svg)](https://github.com/slushsdk/slush/blob/master/LICENSE)

The Slush SDK allows you to spin up L3s on Starknet.

For now this entails running Tendermint nodes and linking them to light clients on Starknet. This repo contains the modified Tendermint files as well as the Cairo contracts (modelled on [Tendermint-Sol](https://github.com/ChorusOne/tendermint-sol)).

Send transactions to tendermint with the [ABCI-CLI](https://docs.tendermint.com/v0.34/app-dev/abci-cli.html).

---

## Requirements

| Tool                                                                                 |  version                                                                       |
| -------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| [Go](https://go.dev/doc/install)                                                     |  [1.17](https://go.dev/doc/go1.17)                                             |
| [Cairo](https://www.cairo-lang.org/docs/quickstart.html)                             |  [0.10.3](https://github.com/starkware-libs/cairo-lang/releases/tag/v0.10.3)   |
| [Starknet Devnet](https://shard-labs.github.io/starknet-devnet/docs/intro#install)   |  [0.4.2](https://github.com/Shard-Labs/starknet-devnet/releases/tag/v0.4.2)    |
| [Protostar](https://docs.swmansion.com/protostar/docs/tutorials/installation)        |  [0.9.1] (https://github.com/software-mansion/protostar/releases/tag/v0.9.1)   |
| Python (with [pyenv](https://github.com/pyenv/pyenv))                                |  [3.9](https://www.python.org/downloads/release/python-390/)                   |

Before installing Starknet Devnet on M1 check [this thread](https://github.com/OpenZeppelin/nile/issues/22).

---

## Starting a single local node

Clone this repo
```sh
git clone https://github.com/slushsdk/slush.git && cd slush
```

Build the binary:
```sh
make build
```

If using testnet:
>Write your alpha-goerli starknet account's private key in hex format into a file called `pkey`:
>```sh
>echo "0x..." > pkey
>```
>Use the init command with  the `--network testnet` and `--account-address` flags:
>```
>./build/slush init validator --home ./valdata --network testnet --account-address 0x...
>```

If using devnet:
>Start Starknet devnet with `--seed 42`:
>```sh
>starknet-devnet --seed 42
>```
>Write the first pre-deployed account's private key into a file called `seed42pkey`:
>```sh
>echo "0xbdd640fb06671ad11c80317fa3b1799d" > seed42pkey
>```
>Use the init command with:
>```
>./build/slush init validator --home ./valdata
>```

Start the local node:
```sh
./build/slush start --proxy-app=kvstore --home ./valdata
```

Cleanup:
```sh
make clean && rm -rf ./valdata
```

---

## Starting a local testnet with multiple nodes

The local testnet spins up the nodes in docker containers. Please make sure that docker desktop is installed and running ([docker desktop installation](https://www.docker.com/products/docker-desktop)).

Start Starknet devnet with `--seed 42` either locally on your machine or in docker:
>locally:
>```sh
>starknet-devnet --seed 42
>```

Write the first pre-deployed account's private key into a file called `seed42pkey`:
```sh
echo "0xbdd640fb06671ad11c80317fa3b1799d" > seed42pkey
```

Build the linux binary:
```sh
make build-linux
```

Start the local testnet (if on linux, make sure to have docker desktop running):
```sh
make localnet-start
```

Cleanup:
```sh
make localnet-stop && make clean
```

---

## Roadmap

Our roadmap is [here](https://geometry.xyz/notebook/the-road-to-slush).

## Join us!
We are looking for [exciting engineers](https://slush.dev/careers) to join!
