// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {UnstoppableVault} from "src/unstoppable/UnstoppableVault.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156.sol";

interface SVM {
    function createUint(uint256 bits, string memory name) external returns (uint256);
    function createUint256(string memory name) external returns (uint256);
    function createAddress(string memory name) external returns (address);
}

contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MCK", 18) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract GoodBorrower is IERC3156FlashBorrower {
    function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata)
        external
        returns (bytes32)
    {
        ERC20(token).approve(msg.sender, amount + fee);
        return keccak256("IERC3156FlashBorrower.onFlashLoan");
    }
}

contract UnstoppableVaultProof is Test {
    SVM internal constant svm = SVM(0xF3993A62377BCd56AE39D773740A5390411E8BC9);

    MockToken token;
    UnstoppableVault vault;
    GoodBorrower borrower;
    address owner;
    address feeRecipient;

    function setUp() public {
        owner = address(0x1111111111111111111111111111111111111111);
        feeRecipient = address(0x2222222222222222222222222222222222222222);
        token = new MockToken();
        vault = new UnstoppableVault(ERC20(address(token)), owner, feeRecipient);
        borrower = new GoodBorrower();
    }

    // Prove: regardless of the relationship between the vault's token balance
    // and its share accounting (the condition the DoS exploit manipulated by
    // directly transferring tokens), a valid flashloan still succeeds.
    function check_flashLoanNeverBlockedByBalanceMismatch() public {
        uint256 deposited = svm.createUint(96, "deposited");
        uint256 donated = svm.createUint(96, "donated");
        uint256 loanAmount = svm.createUint(96, "loanAmount");

        // Establish share accounting via a legitimate deposit.
        address depositor = address(0x3333333333333333333333333333333333333333);
        vm.assume(deposited > 0);
        token.mint(depositor, deposited);
        vm.prank(depositor);
        token.approve(address(vault), deposited);
        vm.prank(depositor);
        vault.deposit(deposited, depositor);

        // Attacker directly donates tokens to break the ERC4626 invariant
        // (totalAssets != convertToShares(totalSupply)). This was the exploit.
        token.mint(address(vault), donated);

        uint256 maxLoan = vault.maxFlashLoan(address(token));
        vm.assume(loanAmount > 0);
        vm.assume(loanAmount <= maxLoan);

        // Fund borrower to be able to pay fee.
        uint256 fee = vault.flashFee(address(token), loanAmount);
        token.mint(address(borrower), fee);

        // The patched contract removed the strict invariant check, so a valid
        // flashloan MUST succeed even after the donation-based DoS attempt.
        bool ok = vault.flashLoan(borrower, address(token), loanAmount, "");
        assert(ok);
    }
}