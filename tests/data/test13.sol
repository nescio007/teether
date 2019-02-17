pragma solidity ^0.4.9;

contract MultiOwned{

  // pointer used to find a free slot in m_owners
  uint public m_numOwners;

  // list of owners
  uint[256] m_owners;

  // index on the list of owners to allow reverse lookup
  mapping(uint => uint) m_ownerIndex;

  // simple single-sig function modifier.
  modifier onlyowner {
    if (isOwner(msg.sender))
      _;
  }

  // constructor is given number of sigs required to do protected "onlymanyowners" transactions
  // as well as the selection of addresses capable of confirming them.
  function initMultiowned(address[] _owners) {
    m_numOwners = _owners.length + 1;
    m_owners[1] = uint(msg.sender);
    m_ownerIndex[uint(msg.sender)] = 1;
    for (uint i = 0; i < _owners.length; ++i)
    {
      m_owners[2 + i] = uint(_owners[i]);
      m_ownerIndex[uint(_owners[i])] = 2 + i;
    }
  }

  function isOwner(address _addr) constant returns (bool) {
    return m_ownerIndex[uint(_addr)] > 0;
  }

}

contract MyContract is MultiOwned{

  function pay(address to, uint amount) onlyowner{
    to.transfer(amount);
  }

}

