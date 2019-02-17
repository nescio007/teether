pragma solidity ^0.4.0;

contract Test{
    
    function withdraw(address to, uint key, uint amount, bytes32 check, bytes32 check2){
        require(check == sha3(to, key, amount));
        require(check2 == sha3(check));
        address recipient = to;
        if(key^0xcafebabe == 0x0badf00d^amount){
            recipient.transfer(amount);
        }
    }
}
