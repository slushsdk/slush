#!/bin/bash

STARKNET_DEVNET_URL=${1:-http://localhost:5050}
ACCOUNT_DIR=${2:-.starknet_accounts}
WEI_AMOUNT=${3:-1000000000000000000000}

if ! command -v starknet &> /dev/null; then
    echo "starknet command could not be found, please install it"
    echo ""
    exit 1
fi

if [ -f $ACCOUNT_DIR/starknet_open_zeppelin_accounts.json ]; then
    echo "Found pre-existing starknet_open_zeppelin_accounts.json, removing it..."
    rm -rf $ACCOUNT_DIR
fi

if curl $STARKNET_DEVNET_URL/is_alive 2>/dev/null | grep -q Alive; then
    echo "Starknet-devnet is already running, continuing..."
else
    echo "Starknet-devnet is not running, please start it"
    echo ""
    exit 1
fi
echo ""

echo "Declaring a new account on devnet..."
declare_output=$(starknet new_account --account "devnet" --gateway_url $STARKNET_DEVNET_URL --feeder_gateway_url $STARKNET_DEVNET_URL --wallet starkware.starknet.wallets.open_zeppelin.OpenZeppelinAccount --network alpha-goerli --account_dir $ACCOUNT_DIR 2>&1)
account_address=$(echo "$declare_output" | grep "Account address: " | awk '{print $3}')
public_key=$(echo "$declare_output" | grep "Public key: " | awk '{print $3}')
if [ -z "$account_address" ] || [ -z "$public_key" ]; then
    echo "Failed to declare account."
    echo "Declare error: $declare_output"
    echo ""
    exit 1
else
  echo "Declared account with address $account_address and public key $public_key"
fi
echo ""

echo "Sending assets to the new account..."
if ! curl -X POST $STARKNET_DEVNET_URL/mint -w '%{http_code}\n' -H 'content-type: application/json' -d '{ "address": "'$account_address'",  "amount": '$WEI_AMOUNT'}' 2>/dev/null | grep -q 200; then
    echo "Failed to send assets to the new account."
    echo ""
    exit 1
else
    echo "Sent $WEI_AMOUNT WEI to $account_address."
fi
echo ""

echo "Deploying the account..."
deploy_output=$(starknet deploy_account --account "devnet" --gateway_url $STARKNET_DEVNET_URL --feeder_gateway_url $STARKNET_DEVNET_URL --wallet starkware.starknet.wallets.open_zeppelin.OpenZeppelinAccount --network alpha-goerli --account_dir $ACCOUNT_DIR 2>&1)
crontract_address=$(echo "$deploy_output" | grep "Contract address: " | awk '{print $3}')
transaction_hash=$(echo "$deploy_output" | grep "Transaction hash: " | awk '{print $3}')
if [ -z "$crontract_address" ] || [ -z "$transaction_hash" ]; then
    echo "Failed to deploy account."
    echo "Deploy error: $deploy_output"
    echo ""
    exit 1
else
    echo "Deployed account with contract address $crontract_address and transaction hash $transaction_hash"
fi
echo ""
echo "Done"
echo ""
