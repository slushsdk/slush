%lang starknet

@external
func up() {
    %{
        import json

        with open('migrations/invoke_input.json', 'r') as infile:
            inputJson = json.load(infile)

        contract_address = inputJson['address']

        invoke(
            contract_address,
            "externalVerifyAdjacent",
            inputJson['calldata'],
            config={
                "max_fee": "auto",
                "wait_for_acceptance": True
            }
        )
    %}

    return ();
}
