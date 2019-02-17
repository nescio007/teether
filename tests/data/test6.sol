pragma solidity ^0.4.0;

contract Test{

    function withdraw(address to, uint key, uint amount){
        uint test = 0;
        if(key&0x1 == 0x1){
            test |= 0x1;
        }
        if(key&0x2 == 0x2){
            test |= 0x2;
        }
        if(key&0x4 == 0x4){
            test |= 0x4;
        }
        if(key&0x8 == 0x8){
            test |= 0x8;
        }
        if(key&0x10 == 0x10){
            test |= 0x10;
        }
        if(key&0x20 == 0x20){
            test |= 0x20;
        }
        if(key&0x40 == 0x40){
            test |= 0x40;
        }
        if(key&0x80 == 0x80){
            test |= 0x80;
        }
        if(key^0xcafebabe == 0x0badf00d^amount){
            to.transfer(amount);
        }
    }
}

