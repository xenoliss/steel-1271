// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";

import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "smart-wallet@v1.0.0/src/CoinbaseSmartWalletFactory.sol";
import {WebAuthn} from "webauthn-sol@v1.0.0/WebAuthn.sol";

contract DeployAndPoC is Script {
    uint256 constant FCL_Elliptic_ZZ_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    function run(string memory rpcUrl) public {
        vm.startBroadcast();

        // 1. Deploy implementation and factory
        address implementation = address(new CoinbaseSmartWallet());
        CoinbaseSmartWalletFactory factory = new CoinbaseSmartWalletFactory(implementation);

        // 2. Create smart wallet
        Vm.Wallet memory k1Wallet = vm.createWallet("k1");
        Vm.Wallet memory r1Wallet = vm.createWallet("r1");
        r1Wallet.addr = address(0x0);
        (r1Wallet.publicKeyX, r1Wallet.publicKeyY) = vm.publicKeyP256(r1Wallet.privateKey);

        bytes[] memory owners = new bytes[](2);
        owners[0] = abi.encode(k1Wallet.addr);
        owners[1] = abi.encode(r1Wallet.publicKeyX, r1Wallet.publicKeyY);

        CoinbaseSmartWallet smartWallet = factory.createAccount({owners: owners, nonce: 0xdeadbeef});

        vm.stopBroadcast();

        // 3. Get user op hash
        bytes32 userOpHash = keccak256(hex"0000000000000000000000001234567890123456789012345678901234567891");
        bytes32 replaySafeHash = smartWallet.replaySafeHash(userOpHash);

        // 4. Sign user op with k1Wallet
        CoinbaseSmartWallet.SignatureWrapper memory k1Sig =
            _eoaSignature({wallet: k1Wallet, ownerIndex: 0, userOpHash: replaySafeHash});
        bytes4 result = smartWallet.isValidSignature({hash: userOpHash, signature: abi.encode(k1Sig)});

        // 5. Sign user op with r1Wallet
        CoinbaseSmartWallet.SignatureWrapper memory r1Sig =
            _webAuthnSignature({wallet: r1Wallet, ownerIndex: 1, userOpHash: replaySafeHash});
        result = smartWallet.isValidSignature({hash: userOpHash, signature: abi.encode(r1Sig)});

        console2.log("To verify k1Sig run:");
        console2.log(_buildCmd(rpcUrl, address(smartWallet), userOpHash, k1Sig));
        console2.log("To verify r1Sig run:");
        console2.log(_buildCmd(rpcUrl, address(smartWallet), userOpHash, r1Sig));
    }

    function _webAuthnSignature(Vm.Wallet memory wallet, uint256 ownerIndex, bytes32 userOpHash)
        private
        pure
        returns (CoinbaseSmartWallet.SignatureWrapper memory sig)
    {
        string memory challengeb64url = Base64.encodeURL(abi.encode(userOpHash));
        string memory clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                challengeb64url,
                '","origin":"https://sign.coinbase.com","crossOrigin":false}'
            )
        );

        // Authenticator data for Chrome Profile touchID signature
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

        bytes32 h = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));

        WebAuthn.WebAuthnAuth memory webAuthn;
        webAuthn.authenticatorData = authenticatorData;
        webAuthn.clientDataJSON = clientDataJSON;
        webAuthn.typeIndex = 1;
        webAuthn.challengeIndex = 23;

        (bytes32 r, bytes32 s) = vm.signP256({privateKey: wallet.privateKey, digest: h});
        if (uint256(s) > (FCL_Elliptic_ZZ_N / 2)) {
            s = bytes32(FCL_Elliptic_ZZ_N - uint256(s));
        }
        webAuthn.r = uint256(r);
        webAuthn.s = uint256(s);

        sig = CoinbaseSmartWallet.SignatureWrapper({ownerIndex: ownerIndex, signatureData: abi.encode(webAuthn)});
    }

    function _eoaSignature(Vm.Wallet memory wallet, uint256 ownerIndex, bytes32 userOpHash)
        private
        returns (CoinbaseSmartWallet.SignatureWrapper memory sig)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet, userOpHash);
        sig = CoinbaseSmartWallet.SignatureWrapper({ownerIndex: ownerIndex, signatureData: abi.encodePacked(r, s, v)});
    }

    function _buildCmd(
        string memory rpcUrl,
        address smartWallet,
        bytes32 userOpHash,
        CoinbaseSmartWallet.SignatureWrapper memory sig
    ) private pure returns (string memory cmd) {
        cmd = string.concat(cmd, "RUST_LOG=info cargo run --bin host --");
        cmd = string.concat(
            cmd, " --eth-wallet-private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        );
        cmd = string.concat(cmd, " --eth-rpc-url ", rpcUrl);
        cmd = string.concat(cmd, " --wallet-address ", vm.toString(smartWallet));
        cmd = string.concat(cmd, " --hash ", vm.toString(userOpHash));
        cmd = string.concat(cmd, " --signature ", vm.toString(abi.encode(sig)));
    }
}
