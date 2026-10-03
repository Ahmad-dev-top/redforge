// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {UnstoppableVault} from "src/unstoppable/UnstoppableVault.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156.sol";

contract TestToken is ERC20 {
    constructor() ERC20("TestToken", "TT", 18) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract GoodBorrower is IERC3156FlashBorrower {
    UnstoppableVault public vault;
    TestToken public token;

    constructor(UnstoppableVault _vault, TestToken _token) {
        vault = _vault;
        token = _token;
    }

    function onFlashLoan(address, address, uint256 amount, uint256 fee, bytes calldata)
        external
        returns (bytes32)
    {
        token.approve(address(vault), amount + fee);
        return keccak256("IERC3156FlashBorrower.onFlashLoan");
    }

    function doFlashLoan(uint256 amount) external {
        vault.flashLoan(this, address(token), amount, "");
    }
}

contract UnstoppableVaultLegitTest is Test {
    TestToken token;
    UnstoppableVault vault;

    address owner = address(0xA11CE);
    address feeRecipient = address(0xFEE);
    address alice = address(0xA);
    address bob = address(0xB);

    uint256 constant INITIAL = 1_000e18;

    function setUp() public {
        token = new TestToken();
        vault = new UnstoppableVault(ERC20(address(token)), owner, feeRecipient);

        token.mint(alice, INITIAL);
        token.mint(bob, INITIAL);

        vm.prank(alice);
        token.approve(address(vault), type(uint256).max);
        vm.prank(bob);
        token.approve(address(vault), type(uint256).max);
    }

    function test_deposit() public {
        vm.prank(alice);
        uint256 shares = vault.deposit(100e18, alice);
        assertEq(shares, 100e18);
        assertEq(vault.balanceOf(alice), 100e18);
        assertEq(vault.totalAssets(), 100e18);
        assertEq(token.balanceOf(address(vault)), 100e18);
    }

    function test_multipleDeposits() public {
        vm.prank(alice);
        vault.deposit(100e18, alice);
        vm.prank(bob);
        vault.deposit(200e18, bob);

        assertEq(vault.balanceOf(alice), 100e18);
        assertEq(vault.balanceOf(bob), 200e18);
        assertEq(vault.totalAssets(), 300e18);
        assertEq(vault.totalSupply(), 300e18);
    }

    function test_withdraw() public {
        vm.prank(alice);
        vault.deposit(100e18, alice);

        vm.prank(alice);
        vault.withdraw(100e18, alice, alice);

        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.totalAssets(), 0);
        assertEq(token.balanceOf(alice), INITIAL);
    }

    function test_partialWithdraw() public {
        vm.prank(alice);
        vault.deposit(100e18, alice);

        vm.prank(alice);
        vault.withdraw(40e18, alice, alice);

        assertEq(vault.balanceOf(alice), 60e18);
        assertEq(vault.totalAssets(), 60e18);
        assertEq(token.balanceOf(alice), INITIAL - 60e18);
    }

    function test_redeem() public {
        vm.prank(alice);
        uint256 shares = vault.deposit(100e18, alice);

        vm.prank(alice);
        uint256 assets = vault.redeem(shares, alice, alice);

        assertEq(assets, 100e18);
        assertEq(vault.balanceOf(alice), 0);
        assertEq(token.balanceOf(alice), INITIAL);
    }

    function test_transferShares() public {
        vm.prank(alice);
        vault.deposit(100e18, alice);

        vm.prank(alice);
        vault.transfer(bob, 40e18);

        assertEq(vault.balanceOf(alice), 60e18);
        assertEq(vault.balanceOf(bob), 40e18);
    }

    function test_transferFromShares() public {
        vm.prank(alice);
        vault.deposit(100e18, alice);

        vm.prank(alice);
        vault.approve(bob, 50e18);

        vm.prank(bob);
        vault.transferFrom(alice, bob, 50e18);

        assertEq(vault.balanceOf(alice), 50e18);
        assertEq(vault.balanceOf(bob), 50e18);
    }

    function test_maxFlashLoan() public {
        vm.prank(alice);
        vault.deposit(500e18, alice);
        assertEq(vault.maxFlashLoan(address(token)), 500e18);
        assertEq(vault.maxFlashLoan(address(0xdead)), 0);
    }

    function test_setFeeRecipient() public {
        vm.prank(owner);
        vault.setFeeRecipient(address(0x1234));
        assertEq(vault.feeRecipient(), address(0x1234));
    }

    function test_pauseAndUnpause() public {
        vm.prank(alice);
        vault.deposit(100e18, alice);

        vm.prank(owner);
        vault.setPause(true);
        assertTrue(vault.paused());

        vm.prank(bob);
        vm.expectRevert();
        vault.deposit(10e18, bob);

        vm.prank(owner);
        vault.setPause(false);
        assertFalse(vault.paused());

        vm.prank(bob);
        vault.deposit(10e18, bob);
        assertEq(vault.balanceOf(bob), 10e18);
    }

    function test_flashLoanFreeDuringGracePeriod() public {
        vm.prank(alice);
        vault.deposit(500e18, alice);

        GoodBorrower borrower = new GoodBorrower(vault, token);
        // amount < maxFlashLoan during grace period => fee is 0
        uint256 amount = 100e18;
        assertEq(vault.flashFee(address(token), amount), 0);

        borrower.doFlashLoan(amount);

        assertEq(vault.totalAssets(), 500e18);
    }

    function test_flashLoanWithFee() public {
        vm.prank(alice);
        vault.deposit(500e18, alice);

        GoodBorrower borrower = new GoodBorrower(vault, token);
        // borrowing full amount triggers fee
        uint256 amount = 500e18;
        uint256 fee = vault.flashFee(address(token), amount);
        assertGt(fee, 0);

        // fund borrower so it can pay the fee
        token.mint(address(borrower), fee);

        borrower.doFlashLoan(amount);

        assertEq(vault.totalAssets(), 500e18);
        assertEq(token.balanceOf(feeRecipient), fee);
    }

    function test_depositStillWorksAfterFlashLoan() public {
        vm.prank(alice);
        vault.deposit(500e18, alice);

        GoodBorrower borrower = new GoodBorrower(vault, token);
        borrower.doFlashLoan(100e18);

        // deposits still work after flash loan (DoS fix)
        vm.prank(bob);
        vault.deposit(100e18, bob);
        assertEq(vault.balanceOf(bob), 100e18);
    }
}