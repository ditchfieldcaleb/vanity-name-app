

/** Vanity Name (Registration) System, or VNS. Definitely not a play on ENS.

Goals:
 - vanity name registration system
 - resistant to frontrunning
 - smaller size name = larger price
 + implement reverse-lookup
 + implement pass-through function execution (more on this later)
 + an address should be able to have mulitple vanities
 + a vanity should map to a single address

Implementation:
 - commit-reveal scheme
 - commit: hash of (msg.sender, name, salt)
 - reveal: provide name, salt, show that hash is valid
 - delay between commit & reveal must be high enough to make frontrunning/censoring infeasible
 - minimum size: 3 characters. 2 or 1 character size names would be too easy to squat
 - fee = 0.01 ETH minimum, 1 ETH maximum
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
 - Maximum size is 32 characters, because this fits in a single storage slot
 - Only a-z supported - ascii codes 0x61-0x7A

**/

// SPDX-License-Identifier: None

pragma solidity 0.8.7;

contract VNS {
    // todo: events

    uint constant public registrationPeriod = 365 days;
    uint constant public requiredRegistrationDelay = 5 minutes;
    uint constant public renewalPeriod = 1 weeks;

    uint constant public minNameLength = 3;
    uint constant public maxNameLength = 32;

    uint constant public minFee = 0.01 ether;
    uint constant public maxFee = 1 ether;

    struct VanityRegistration {
        bytes32 name;
        address owner;
        uint expiration;    /* unix timestamp                    */
        uint amountLocked;  /* ether locked by this name         */
    }

    struct UserInfo {
        bytes32 pendingRegHash;
        uint pendingRegCompletionTime;

        uint totalAmountLocked;
        bytes32[] ownedNames;
    }
    
    mapping(address => UserInfo) userInfo;
    mapping(bytes32 => VanityRegistration) vanityRegistrationsByName;

    constructor() { }

    fallback() payable external {
        revert("You cannot directly send ETH to VNS.");
    }

    receive() payable external {
        revert("You cannot directly send ETH to VNS");
    }

    function beginRegistration(bytes32 nameHash) public {
        userInfo[msg.sender].pendingRegHash = nameHash;
        userInfo[msg.sender].pendingRegCompletionTime = block.timestamp + requiredRegistrationDelay;
    }

    function completeRegistration(bytes32 name, bytes32 salt) public payable {
        require(userInfo[msg.sender].pendingRegHash != 0x0, "No pending registration.");
        require(userInfo[msg.sender].pendingRegCompletionTime > block.timestamp, "Delay period not yet complete.");
        require(msg.value == getLockAmount(name), "Invalid fee amount.");
        require(keccak256(abi.encodePacked(msg.sender, name, salt)) == userInfo[msg.sender].pendingRegHash, "Invalid input. Please check the salt.");
        require(isValidName(name), "Invalid name, can only contain a-z lowercase");        

        if(vanityRegistrationsByName[name].owner != address(0x0)) {
            if (vanityRegistrationsByName[name].expiration < block.timestamp) {
                revert("Name already registered.");
            } else {
                unRegisterName(name);
            }
        }

        // Name is definitely not registered at this point.
        vanityRegistrationsByName[name] = VanityRegistration(name, msg.sender, block.timestamp + registrationPeriod, msg.value);
        userInfo[msg.sender].totalAmountLocked += msg.value;
        userInfo[msg.sender].pendingRegHash = 0x0;
        userInfo[msg.sender].pendingRegCompletionTime = 0;
        userInfo[msg.sender].ownedNames.push(name);
    }

    function renewRegistration(bytes32 name) public {
        require(vanityRegistrationsByName[name].owner == msg.sender, "You do not own this name.");
        require(block.timestamp >= vanityRegistrationsByName[name].expiration - renewalPeriod, "Name not yet eligibile for rewnewal.");

        vanityRegistrationsByName[name].expiration += renewalPeriod;
    }

    function unRegisterName(bytes32 name) public {
        require(vanityRegistrationsByName[name].owner == msg.sender || vanityRegistrationsByName[name].expiration <= block.timestamp, "Name must be expired or you must own this name.");

        uint amountToTransfer = vanityRegistrationsByName[name].amountLocked;

        delete vanityRegistrationsByName[name];

        payable(msg.sender).transfer(amountToTransfer);
    }

    function lookupAndExecute(bytes32 name, uint value, bytes calldata data) public payable {
        require(vanityRegistrationsByName[name].owner != address(0x0), "Name not registered.");
        require(vanityRegistrationsByName[name].expiration > block.timestamp, "Name has expired.");
        require(msg.value == value, "Must send exactly the value specified.");

        address destination = vanityRegistrationsByName[name].owner;

        destination.call{value: value}(data);
    }

    function getLockAmount(bytes32 name) public pure returns (uint) {
        uint length = getNameLength(name);
        
        require(length >= minNameLength && length <= maxNameLength, "Name must be between 3 and 32 characters.");

        return maxFee / (length - minNameLength + 1);
    }

    /** 1 byte per character. 0x00 byte is a terminator. **/
    function getNameLength(bytes32 name) public pure returns (uint) {
        
        // 1 byte per character, maximum 32 characters
        for (uint i = 0; i < 32; i++) {
            if (name[i] == 0x0) {
                return i;
            }
        }
        
        return 32;
    }

    function isValidName(bytes32 name) public pure returns (bool) {
        uint8 minAllowedAsciiCode = 0x61; // a
        uint8 maxAllowedAsciiCode = 0x7A; // z
    
        for (uint i = 0; i < 32; i++) {
            if ((uint8(name[i]) < minAllowedAsciiCode || uint8(name[i]) > maxAllowedAsciiCode) && name[i] != 0x00) {
                return false;
            }
        }

        return true;
    }
}