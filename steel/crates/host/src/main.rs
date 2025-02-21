// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This application demonstrates how to send an off-chain proof request
// to the Bonsai proving service and publish the received proofs directly
// to your deployed app contract.

use alloy_primitives::{hex::FromHex, Address, Bytes, B256};
use anyhow::{Context, Result};
use base64::prelude::*;
use borsh::to_vec;
use clap::Parser;
use guests::EIP_1271_ELF;
use revm::primitives::SpecId;
use risc0_steel::{
    alloy::{
        network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner, sol,
    },
    config::ChainSpec,
    ethereum::EthEvmEnv,
    host::BlockNumberOrTag,
    Contract,
};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

sol! {
    #[derive(Debug)]
    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 result);
    }
}

/// Simple program to create a proof to increment the Counter contract.
#[derive(Parser)]
struct Args {
    /// Ethereum private key
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum RPC endpoint URL
    #[clap(long, env)]
    eth_rpc_url: Url,

    /// Ethereum block to use as the state for the contract call
    #[clap(long, env, default_value_t = BlockNumberOrTag::Parent)]
    execution_block: BlockNumberOrTag,

    /// Address of the wallet contract
    #[clap(long)]
    wallet_address: Address,

    /// Hash to validate
    #[clap(long)]
    hash: B256,

    /// Signature to validate
    #[clap(long)]
    signature: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::try_parse()?;

    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.eth_rpc_url);

    let builder = EthEvmEnv::builder()
        .provider(provider.clone())
        .block_number_or_tag(args.execution_block);

    let mut env = builder.build().await?;

    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ChainSpec::new_single(31337, SpecId::CANCUN));

    // Prepare the function call
    let signature = Bytes::from_hex(&args.signature).expect("Invalid signature hex string");
    let call = IERC1271::isValidSignatureCall {
        hash: args.hash,
        signature: signature.clone(),
    };

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(args.wallet_address, &mut env);
    let result = contract.call_builder(&call).call().await?.result;
    assert!(result == [0x16, 0x26, 0xba, 0x7e]);

    // Finally, construct the input from the environment.
    // There are two options: Use EIP-4788 for verification by providing a Beacon API endpoint,
    // or use the regular `blockhash' opcode.
    let evm_input = env.into_input().await?;

    // Create the steel proof.
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&args.wallet_address)?
            .write(&args.hash)?
            .write(&signature)?
            .build()
            .unwrap();

        default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            EIP_1271_ELF,
            &ProverOpts::groth16(),
        )
    })
    .await?
    .context("failed to create proof")?;

    println!(
        "Base64 encoded receipt: {:?}",
        BASE64_STANDARD.encode(to_vec(&prove_info.receipt).unwrap())
    );

    Ok(())
}
