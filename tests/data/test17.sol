pragma solidity ^0.4.9;

contract destroyable{

  function destroy(address target){
    suicide(target);
  }

}

contract MyContract is destroyable{

}

