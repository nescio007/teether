pragma solidity ^0.4.0;

contract Test{

    struct Transaction{
        address to;
        uint amount;
    }

    mapping (bytes32 => Transaction) transactions;

    address owner;
    
    function set_owner(address new_owner){
        owner = new_owner;
    }
    
    function new_transaction(address to, uint amount) returns (bytes32){
        bytes32 token = sha3(to, amount);
        Transaction storage t = transactions[token];
        t.to = to;
        t.amount += amount;
        return token;
    }
    
    function approve(bytes32 token){
        Transaction storage t = transactions[token];
        t.to.transfer(t.amount);
        delete transactions[token];
    }
    
}

