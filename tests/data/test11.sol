pragma solidity ^0.4.0;


contract Test{

    bool check1 = false;
    bool check2 = false;

    function mark(uint which){
        if(which == 1){
            check1 = true;
        }else if(which == 2){
            check2 = true;
        }
    }
    
    function transfer(address to, uint amount) {
        require(check1);
        require(check2);
        to.transfer(amount);
    }
    
}
