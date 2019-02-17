pragma solidity ^0.4.9;

contract MyContract{

    uint var1;
    uint var2;
    uint var3;
    uint var4;
    uint var5;
    uint var6;
    uint var7;
    uint var8;
    address receiver;

    function set1(uint new1) public{
        var1 = new1;
    }

    function set2(uint new2) public{
        var2 = new2;
    }

    function set3(uint new3) public{
        var3 = new3;
    }

    function set4(uint new4) public{
        var4 = new4;
    }

    function set5(uint new5) public{
        var5 = new5;
    }

    function set6(uint new6) public{
        var6 = new6;
    }

    function set7(uint new7) public{
        var7 = new7;
    }

    function set8(uint new8) public{
        var8 = new8;
    }

    function setreceiver(address newreceiver) public{
        require(var8 == 42);
        receiver = newreceiver;
    }

    function pay(uint amount) public{
        receiver.transfer(amount);
    }

}

