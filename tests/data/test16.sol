pragma solidity >=0.4.9;

contract updateable{

  address lib;

  function update(address new_library) public{
    lib = new_library;
  }

  function () payable external{
    lib.delegatecall(msg.data);
  }

}

contract MyContract is updateable{

}

