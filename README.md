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

| Requirements                                                                                |     |
| ------------------------------------------------------------------------------------------- | --- |
| Go tested with 1.19                                                                         |
| [Starknet Devnet](https://shard-labs.github.io/starknet-devnet/docs/intro#install)   v0.3.5 |
| [Protostar](https://github.com/software-mansion/protostar)      v.0.6                       |
| Python 3.9.14 (use [pyenv](https://github.com/pyenv/pyenv))                                 |

Before installing Starknet Devnet on M1 check [this thread](https://github.com/OpenZeppelin/nile/issues/22).

## Quick Start


1. Clone this repo
2. Start the Starknet devnet. This will take up the view of Terminal 
   - `starknet-devnet —seed=42`
3. Open a new terminal. Run the following at the root of this repo
   - `make build`
   - `./build/slush init validator --home ./valdata`
   - `./build/slush start --proxy-app=kvstore --home ./valdata`



## Roadmap

Our roadmap is [here](https://geometry.xyz/notebook/the-road-to-slush).

## Join us!
We are looking for [exciting engineers](https://slush.dev/careers) to join!
