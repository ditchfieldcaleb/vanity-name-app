

/** Vanity Name (Registration) System, or VNS. Definitely not a play on ENS.

Goals:
 - vanity name registration system
 - resistant to frontrunning
 - smaller size name = larger price
 + implement reverse-lookup
 + implement pass-through function execution (more on this later)'
 + an address should be able to have mulitple vanities
 + a vanity should map to a single address

Implementation:
 - commit-reveal scheme
 - commit: hash of (msg.sender, name, salt)
 - reveal: provide name, salt, show that hash is valid
 - delay between commit & reveal must be high enough to make frontrunning/censoring infeasible
 - minimum size: 3 characters. 2 or 1 character size names would be too easy to squat
 - fee = 0.01 ETH minimum, 1 ETH maximum. 10 chars or more = 0.01 ETH, 3 chars = 1 ETH
 - if a vanity has owner 0x0, it is not registered.

Caveats:
 - registration period = 1 year. a production version of this app would have this period changeable by the owner.
 - a more advanced system would have the ability for the owner of a vanity to change where it points to, while still keeping ownership - similar to ENS.
 - this would be a bit more resistant to name-squatters if the payment was required @ "beginRegistration" instead of "completeRegistration". with the current
   implementation, an attacker would still have to use a different address per name, but on a chain such as bsc or matic, this is trivial - tx fees are minimal.
   said attacker would send many transactions to begin the registration for all 3-4 letter names - perhaps even 5-letter names - and complete the registration via
   frontrunning when it sees an attempt to register it. if we moved the payment to the "beginRegistration" part, the attacker would have to commit a very large amount
   of currency to do the same attack.

Notes & Attribution:
 - Helpful Notes on Commit/Reveal Scheme: https://medium.com/gitcoin/commit-reveal-scheme-on-ethereum-25d1d1a25428
 - Salt is necessary to prevent brute-force-name-guessing attacks
 - Maximum size is 51 characters. Why? We can encode a-z with only 5 bits, so using a whole uint256/bytes32 storage slot we can get up to 51 characters
 - Of course, this only works with the standard English alphabet! Other languages not supported.

**/

// SPDX-License-Identifier: None

pragma solidity 0.8.7;

contract VNS {
    // todo: events

    uint constant public registrationPeriod = 60 minutes * 24 /*hours*/ * 365 /*days*/;
    uint constant public requiredDelay = 5 minutes;

    uint constant public minNameLength = 3;
    uint constant public maxNameLength = 51;
    uint constant public minFeeLength = 10;

    uint constant public minFee = 0.01 ether;
    uint constant public maxFee = 1 ether;

    mapping(address => bytes32) public inProgressRegHashes;
    mapping(address => uint) public inProgressRegCompletionTimes;

    mapping(address => uint) public addressToLockedBalance;

    mapping(bytes32 => address) public vanityToAddress;
    mapping(bytes32 => uint) public vanityToExpirationDatetime;

    mapping(address => bytes32[]) public addressToVanities;

    constructor() { }

    fallback() payable external {
        revert("You cannot directly send ETH to VNS.");
    }

    receive() payable external {
        revert("You cannot directly send ETH to VNS");
    }

    function beginRegistration(bytes32 hash) public{
        inProgressRegHashes[msg.sender] = hash;
        inProgressRegCompletionTimes[msg.sender] = block.timestamp + requiredDelay;
    }

    function completeRegistration(bytes32 name, bytes32 salt) public payable {
        require(inProgressRegHashes[msg.sender] != bytes32(0x0), "No pending registration to complete!");
        require(inProgressRegCompletionTimes[msg.sender] <= block.timestamp, "Too early to complete registration.");
        require(inProgressRegHashes[msg.sender] == keccak256(abi.encodePacked(msg.sender, name, salt)), "Name and salt do not match existing hash.");

        uint costOfVanity = lengthToPrice(getNameLength(name));
        require(msg.value >= costOfVanity, "Must pay at least the cost of the name.");

        addressToLockedBalance[msg.sender] += costOfVanity;

        inProgressRegHashes[msg.sender] = 0x0;
        inProgressRegCompletionTimes[msg.sender] = 0x0;

        vanityToAddress[name] = msg.sender;
        vanityToExpirationDatetime[name] = block.timestamp + registrationPeriod;

        addressToVanities[msg.sender].push(name);

        if (costOfVanity > msg.value) {
            payable(msg.sender).transfer(msg.value - costOfVanity);
        }
    }

    function getNameLength(bytes32 name) public view returns (uint) {
        // todo: implement custom 5-bits a-z encoding
    }

    function lengthToPrice(uint length) public pure returns (uint) {
        if (length < minNameLength) {
            revert("Name too short");
        } else if (length < minFeeLength) {
            return maxFee / (length - minNameLength + 1);
        } else {
            return minFee;
        }
    }
}