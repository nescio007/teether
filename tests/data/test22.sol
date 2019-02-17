pragma solidity ^0.4.9;

contract SymbolicRead{
    
    mapping(bytes32 => uint) approved;

  function pay(address to, uint amount, uint secret) {
    require(secret != 0);
    bytes32 key = keccak256(msg.data);
    if(approved[key] == secret){
        to.transfer(amount);
    }else{
        approved[key] = secret;
    }
  }
}
