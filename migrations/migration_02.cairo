%lang starknet

@external
func up() {
    %{
        import json

        with open('invoke_input.json', 'r') as infile:
            inputJson = json.load(infile)
        #send here instead: 0x029fff01b33ffe66338d42c351e433ff7857dbdd092fe085760adc943e9d70ca
        print(inputJson.keys())
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
