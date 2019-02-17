pragma solidity ^0.4.9;

contract MyContract{

    function pay(uint amount){

        if(msg.sender == address(0)){
            address(0).transfer(amount);
        }else{
            if(msg.sender == address(1)){
                address(1).transfer(amount);
            }else{
                if(msg.sender == address(2)){
                    address(2).transfer(amount);
                }else{
                    if(msg.sender == address(3)){
                        address(3).transfer(amount);
                    }else{
                        if(msg.sender == address(4)){
                            address(4).transfer(amount);
                        }else{
                            if(msg.sender == address(5)){
                                address(5).transfer(amount);
                            }else{
                                if(msg.sender == address(6)){
                                    address(6).transfer(amount);
                                }else{
                                    if(msg.sender == address(7)){
                                        address(7).transfer(amount);
                                    }else{
                                        if(msg.sender == address(8)){
                                            address(8).transfer(amount);
                                        }else{
                                            if(msg.sender == address(9)){
                                                address(9).transfer(amount);
                                            }else{
                                                msg.sender.transfer(amount);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

}

