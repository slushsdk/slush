%lang starknet

@external
func up() {
    %{
        import json

        with open('invoke_input.json', 'r') as infile:
            inputJson = json.load(infile)
        with open('contract_address', 'r') as infile:
            contract_address_hex = infile.readline()

        contract_address = int(contract_address_hex.rstrip(), 16)

        print("contract_address")
        print(contract_address)

        invoke(
            contract_address,
            "externalVerifyAdjacent",
            inputJson,
            config={
                "max_fee": "auto",
                "wait_for_acceptance": True
            }
        )
    %}

    return ();
}
