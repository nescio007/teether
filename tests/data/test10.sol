pragma solidity ^0.4.0;


contract owned {
    function owned() { owner = msg.sender; }
    address owner;

    // This contract only defines a modifier but does not use
    // it - it will be used in derived contracts.
    // The function body is inserted where the special symbol
    // "_;" in the definition of a modifier appears.
    // This means that if the owner calls this function, the
    // function is executed and otherwise, an exception is
    // thrown.
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

contract Test is owned{

    struct Transaction{
        address to;
        uint amount;
    }

    mapping (bytes32 => Transaction) transactions;

    function set_owner(address new_owner){
        owner = new_owner;
    }
    
    function new_transaction(address to, uint amount) onlyOwner returns (bytes32) {
        bytes32 token = sha3(to, amount);
        Transaction storage t = transactions[token];
        t.to = to;
        t.amount += amount;
        return token;
    }
    
    function approve(bytes32 token) onlyOwner {
        Transaction storage t = transactions[token];
        t.to.transfer(t.amount);
        delete transactions[token];
    }
    
}
