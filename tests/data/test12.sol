pragma solidity ^0.4.0;


contract Test{

    function foo() returns (uint) {
        return 2;
    }
    
    function bar() returns (uint){
        uint x = foo();
        return x*2;
    }
    
    function baz() returns (uint){
        uint y = foo();
        return y/2;
    }
    
}
