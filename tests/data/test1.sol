pragma solidity ^0.4.0;

contract Test{
    
    function withdraw(address to, uint key, uint amount){
        address recipient = to;
        if(key^0xcafebabe == 0x0badf00d^amount){
            recipient.transfer(amount);
        }
    }
}
