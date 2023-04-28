// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../contracts/ETH_Factory.sol";
import "../../contracts/ETH_Keycrypt.sol";

// import openzeppelin's ERC20 interface
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@solady/src/utils/ERC1967Factory.sol";

contract FactoryTest is Test {
    using UserOperationLib for UserOperation;

    uint256 mainnetFork;
    ETH_Factory public ethFactory;
    ERC1967Factory public soladyFactory;
    ETH_Keycrypt public keycrypt;
    address public owner;
    address public guardian1;
    address public guardian2;
    IEntryPoint public entryPoint = IEntryPoint(0x0576a174D229E3cFA37253523E645A78A0C91B57);

    function setUp() public {
        // create eth mainnet fork and deploy ETH_Factory.sol to it
        mainnetFork = vm.createFork('https://eth-mainnet.g.alchemy.com/v2/BKt4FdcCBCJR7b5-KAdqNfoovPA7rFcx');
        vm.selectFork(mainnetFork);
        owner = vm.addr(19);
        guardian1 = vm.addr(20);
        guardian2 = vm.addr(21);
    }

    function test_ETH_FactoryDeployment() public {
        ethFactory = new ETH_Factory(entryPoint);
        uint gas = gasleft();
        keycrypt = ethFactory.createAccount(owner, guardian1, guardian2, 0);
        uint gasUsed = gas - gasleft();
        console.log("gas used:", gasUsed);
        console.log("keycrypt address: %s", address(keycrypt));
    }

    function test_ERC1967FactoryDeployment() public {
        soladyFactory = ERC1967Factory(0x0000000000006396FF2a80c067f99B3d2Ab4Df24);
        bytes memory data = abi.encodeWithSelector(ETH_Keycrypt.initialize.selector, owner, guardian1, guardian2);
        ETH_Keycrypt keycryptImpl = new ETH_Keycrypt(entryPoint);
        uint gas = gasleft();
        address keycryptAddr = soladyFactory.deployDeterministicAndCall(address(keycryptImpl), owner, 0, data);
        uint gasUsed = gas - gasleft();
        console.log("gas used:", gasUsed);
        keycrypt = ETH_Keycrypt(payable(keycryptAddr));
        console.log("keycrypt address: %s", keycryptAddr);
    }

}