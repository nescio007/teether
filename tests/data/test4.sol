pragma solidity ^0.4.0;

contract Test{
    
    address public to;

    function set_to() {
        to = msg.sender;
    }

    
    function withdraw(uint key, uint amount){ 
        if(key^0xcafebabe == 0x0badf00d^amount){
            to.transfer(amount);
        }
    }
}
