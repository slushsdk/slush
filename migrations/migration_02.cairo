%lang starknet

@external
func up() {
    %{
        import json

        with open('invoke_input.json', 'r') as infile:
            inputJson = json.load(infile)
        #send here instead: 0x029fff01b33ffe66338d42c351e433ff7857dbdd092fe085760adc943e9d70ca
        contract_address = 2681321777313866831207172647830701585786458434608807373285616162347166442907

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
