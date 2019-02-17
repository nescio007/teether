pragma solidity ^0.4.9;

contract SymbolicRead{
    
    mapping(bytes32 => bool) approved;

  function pay(address to, uint amount) {
    bytes32 key = sha3(msg.data);
    if(approved[key]){
        to.transfer(amount);
    }else{
        approved[key] = true;
    }
  }
}
