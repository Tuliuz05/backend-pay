pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

template Withdraw() {
    signal input root;             
    signal input nullifierHash;    
    signal input invoiceId;        
    
    signal input secret;           
    signal input nullifier;        

    component poseidonNullifier = Poseidon(1);
    poseidonNullifier.inputs[0] <== nullifier;
    nullifierHash === poseidonNullifier.out;

    component poseidonCommitment = Poseidon(2);
    poseidonCommitment.inputs[0] <== secret;
    poseidonCommitment.inputs[1] <== nullifier;
    signal commitment <== poseidonCommitment.out;

    
    signal invoiceSquare <== invoiceId * invoiceId;
}

component main {public [root, nullifierHash, invoiceId]} = Withdraw();