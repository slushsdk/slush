%lang starknet

@external
func up() {
    %{
        import json

        with open('invoke_input.json', 'r') as infile:
            inputJson = json.load(infile)

        contract_address = 2681321777313866831207172647830701585786458434608807373285616162347166442907

        invoke(
            contract_address,
            "externalVerifyAdjacent",
            inputJson,
            config={
                "auto_estimate_fee": True,
                "wait_for_acceptance": True
            }
        )
    %}

    return ();
}
