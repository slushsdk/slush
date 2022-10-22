%lang starknet

@external
func up() {
     
    %{
        declare("./build/main.json")
        deploy_contract("./build/main.json",  config={"wait_for_acceptance": True})
    %}

    return ();
}
