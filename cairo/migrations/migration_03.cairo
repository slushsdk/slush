%lang starknet

@external
func up() {
    alloc_locals;
    
    %{
        import json

        with open('invoke_input.json', 'r') as infile:
            inputJson = json.load(infile)

        #deploy the main.cairo contract
        # get contract address
        # invoke externalVerifyAdjacent

        print(inputJson)

        declare("./build/main.json", config={"max_fee": "auto"})
        contract_address = deploy_contract("./build/main.json",  config={"wait_for_acceptance": True}).contract_address
        #prepared = prepare(declared)
        #ids.contract_address = deploy(prepared).contract_address
        print(contract_address)
        print('This is line 20')
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