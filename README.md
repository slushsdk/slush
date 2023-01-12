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
| [Protostar](https://docs.swmansion.com/protostar/docs/tutorials/installation)        |  [0.9.1](https://github.com/software-mansion/protostar/releases/tag/v0.9.1)   |
| Python (with [pyenv](https://github.com/pyenv/pyenv))                                |  [3.9](https://www.python.org/downloads/release/python-390/)                   |

Before installing Starknet Devnet on M1 check [this thread](https://github.com/OpenZeppelin/nile/issues/22).

---

## Starting a single local node

Clone this repo
```sh
git clone https://github.com/slushsdk/slush.git && cd slush
```
You can deploy on devnet or alpha-goerli testnet. If deploying on devnet start Starknet devnet with `--seed 42` either locally on your machine or in docker:
>locally:
>```sh
>starknet-devnet --seed 42
>```
>docker (linux/amd64):
>```sh
>docker run --rm -p 5050:5050 -d --name devnet shardlabs/starknet-devnet --seed 42
>```
>docker (linux/arm64):
>```sh
>docker run --rm -p 5050:5050 -d --name devnet shardlabs/starknet-devnet:latest-arm --seed 42
>```

Write the first pre-deployed account's private key into a file called `seed42pkey`:
```sh
echo "0xbdd640fb06671ad11c80317fa3b1799d" > seed42pkey
```
Alternatively, if deploying on alpha-goerli testnet, write your Argent wallet private key into pkey file: 
```sh
echo "0x..." > pkey
```

Build the binary:
```sh
make build
```

Init (if deploying on alpha-goerli testnet add the "--network testnet" flag):
```sh
./build/slush init validator --home ./valdata
```

Start the local node:
```sh
./build/slush start --proxy-app=kvstore --home ./valdata
```

Cleanup:
```sh
make clean && rm -rf ./valdata
```

---

## Starting a testnet with watcher nodes on a different machines

You can deploy alpha-goerli testnet. 

On your chosen validator node:

> Write your Argent wallet private key into pkey file: 
>```sh
>echo "0x..." > pkey
>```
>Build the binary:
>```
>make build
>```
>Init:
>```sh
>./build/slush init validator --home ./valdata --network testnet
>```
>Run the inputs for the non-validator nodes. Execute the output on the non-validator nodes:
>```sh 
>python multiple-non-validator-node-steps.py
>```
>And you also need to start the validator node on the original machine, with:
>```
>./build/slush start --home ./valdata --proxy-app=kvstore 
>```


<br/>

Initialize a non-validator node with the outputs of the multiple-non-validator-node-steps.py script. These will look like:

<br/>

> Initialise the non-validator node. 
>```
> ./build/slush init full --home ./valdata
>```
>Copy the content of the valdata/config/genesis.json file from the validator node to the valdata/config folder of the other non-validator computers. 
>
>Run the following command to start a non-validator node:
>```
>./build/slush start --home ./valdata --proxy-app=kvstore --p2p.persistent-peers "SOME-LONG-ADDRESS@SOME-IP"
>```

Cleanup:
```sh
make clean && rm -rf ./valdata
```

---

## Roadmap

Our roadmap is [here](https://geometry.xyz/notebook/the-road-to-slush).

## Join us!
We are looking for [exciting engineers](https://slush.dev/careers) to join!
