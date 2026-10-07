//! One exact owner operation a factory-derived or existing (imported) Kernel
//! 0.4.0 account's root signs, and its signed artifact (`owner-operation.ts`).
//! An existing account is deployed, so its operation carries no factory.
//!
//! The root signs the EntryPoint 0.9 UserOperation hash, which binds chain,
//! EntryPoint, account, nonce, calls, gas, factory and paymaster. Capture
//! proves only address-free facts, exactly as TypeScript does; the account's
//! address (derived, or the existing profile's own), factory and EntryPoint
//! are proven by
//! [`verify_owner_operation_binding`], as the SDK's `verifyOwnerOperation`
//! does. Root signatures are verified by the relay, never here.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolValue;
use serde_json::{Value, json};

use crate::capture::{
    MAX_SAFE_INTEGER_U64, Record, ZERO_ADDRESS, capture_address, exact_record, field,
    is_canonical_decimal, is_lower_hex_bytes, safe_integer,
};
use crate::error::{ErrorCode, OrFail, ProtocolResult, ensure};
use crate::identity::{
    KernelAccountProfile, KernelDerivedAccountProfile, KernelExistingAccountVersion,
    KernelFactoryRoute, OwnerCredentialProfile, address_of, b256_of, bytes_of,
    capture_kernel_account, hex_hash,
};
use crate::kernel_account::{derive_kernel_v4_account_address, root_package};

pub const OWNER_OPERATION_REQUEST_VERSION: &str = "oaath.owner-operation-request/v1";
pub const SIGNED_OWNER_OPERATION_VERSION: &str = "oaath.signed-owner-operation/v1";
pub const MAX_OWNER_OPERATION_CALLS: usize = 16;

/// EntryPoint 0.9, which every Kernel 0.4.0 account uses.
const ENTRY_POINT_V09: &str = "0x433709009b8330fda32311df1c2afa402ed8d009";
/// `KernelFactory` for EntryPoint 0.9.
const KERNEL_V4_FACTORY: &str = "0x3d6d678742e276b6388fd06c1b8ecd19e2d64c2d";

const CODE: ErrorCode = ErrorCode::SigningRequestInvalid;
const BINDING: ErrorCode = ErrorCode::KernelRuntimeBindingMismatch;
const MAX_DATA_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;
const PAYMASTER_SIGNATURE_MAGIC: &str = "22e325a297439656";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerOperationCall {
    pub target: String,
    pub value: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerOperationFactory {
    pub address: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerOperationPaymaster {
    pub address: String,
    pub verification_gas_limit: String,
    pub post_op_gas_limit: String,
    pub data: String,
}

/// EntryPoint 0.9's unpacked unsigned operation; integers are canonical decimals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerUserOperation {
    pub sender: String,
    pub nonce: String,
    pub call_data: String,
    pub call_gas_limit: String,
    pub verification_gas_limit: String,
    pub pre_verification_gas: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub factory: Option<OwnerOperationFactory>,
    pub paymaster: Option<OwnerOperationPaymaster>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerOperationRequest {
    pub account: KernelAccountProfile,
    pub chain_id: u64,
    pub entry_point: String,
    pub calls: Vec<OwnerOperationCall>,
    pub user_operation: OwnerUserOperation,
    /// The EntryPoint 0.9 UserOperation hash: the digest the root signs.
    pub user_operation_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOwnerOperation {
    pub request: OwnerOperationRequest,
    pub signature: String,
}

fn address(value: &Value, allow_zero: bool) -> ProtocolResult<String> {
    capture_address(value)
        .filter(|text| allow_zero || text != ZERO_ADDRESS)
        .or_fail(CODE)
}

fn bytes(value: &Value, maximum: usize) -> ProtocolResult<String> {
    value
        .as_str()
        .filter(|text| is_lower_hex_bytes(text) && text.len() <= 2 + maximum * 2)
        .map(str::to_owned)
        .or_fail(CODE)
}

fn uint(value: &Value, bits: usize) -> ProtocolResult<String> {
    let text = value.as_str().filter(|text| is_canonical_decimal(text, 78));
    let number = text.and_then(|text| U256::from_str_radix(text, 10).ok());
    ensure(number.is_some_and(|number| number.bit_len() <= bits), CODE)?;
    Ok(text.expect("checked").to_owned())
}

fn u256(text: &str) -> U256 {
    U256::from_str_radix(text, 10).expect("captured uint")
}

fn capture_calls(value: &Value) -> ProtocolResult<Vec<OwnerOperationCall>> {
    let entries = value.as_array().or_fail(CODE)?;
    ensure(
        (1..=MAX_OWNER_OPERATION_CALLS).contains(&entries.len()),
        CODE,
    )?;
    entries
        .iter()
        .map(|entry| {
            let call = exact_record(entry, &["target", "value", "data"]).or_fail(CODE)?;
            Ok(OwnerOperationCall {
                target: address(field(call, "target"), true)?,
                value: uint(field(call, "value"), 256)?,
                data: bytes(field(call, "data"), MAX_DATA_BYTES)?,
            })
        })
        .collect()
}

fn capture_user_operation(value: &Value) -> ProtocolResult<OwnerUserOperation> {
    let op: &Record = exact_record(
        value,
        &[
            "sender",
            "nonce",
            "callData",
            "callGasLimit",
            "verificationGasLimit",
            "preVerificationGas",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "factory",
            "paymaster",
        ],
    )
    .or_fail(CODE)?;
    let max_fee_per_gas = uint(field(op, "maxFeePerGas"), 120)?;
    let max_priority_fee_per_gas = uint(field(op, "maxPriorityFeePerGas"), 120)?;
    ensure(
        u256(&max_priority_fee_per_gas) <= u256(&max_fee_per_gas),
        CODE,
    )?;
    let factory = match field(op, "factory") {
        Value::Null => None,
        value => {
            let record = exact_record(value, &["address", "data"]).or_fail(CODE)?;
            Some(OwnerOperationFactory {
                address: address(field(record, "address"), false)?,
                data: bytes(field(record, "data"), MAX_DATA_BYTES)?,
            })
        }
    };
    let paymaster = match field(op, "paymaster") {
        Value::Null => None,
        value => {
            let record = exact_record(
                value,
                &["address", "verificationGasLimit", "postOpGasLimit", "data"],
            )
            .or_fail(CODE)?;
            let data = bytes(field(record, "data"), MAX_DATA_BYTES)?;
            // The hash would omit a detached paymaster signature; this artifact has none.
            ensure(!data.ends_with(PAYMASTER_SIGNATURE_MAGIC), CODE)?;
            Some(OwnerOperationPaymaster {
                address: address(field(record, "address"), false)?,
                verification_gas_limit: uint(field(record, "verificationGasLimit"), 120)?,
                post_op_gas_limit: uint(field(record, "postOpGasLimit"), 120)?,
                data,
            })
        }
    };
    Ok(OwnerUserOperation {
        sender: address(field(op, "sender"), false)?,
        nonce: uint(field(op, "nonce"), 256)?,
        call_data: bytes(field(op, "callData"), MAX_DATA_BYTES * 2)?,
        call_gas_limit: uint(field(op, "callGasLimit"), 120)?,
        verification_gas_limit: uint(field(op, "verificationGasLimit"), 120)?,
        pre_verification_gas: uint(field(op, "preVerificationGas"), 120)?,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        factory,
        paymaster,
    })
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("four bytes")
}

/// Kernel's ERC-7579 `execute`: single call type for one call, batch otherwise.
fn kernel_execution(calls: &[OwnerOperationCall]) -> String {
    let (mode, execution) = match calls {
        [call] => {
            let mut packed = address_of(&call.target).to_vec();
            packed.extend_from_slice(&u256(&call.value).to_be_bytes::<32>());
            packed.extend_from_slice(&bytes_of(&call.data));
            (B256::ZERO, packed)
        }
        _ => {
            let batch: Vec<(Address, U256, Bytes)> = calls
                .iter()
                .map(|call| {
                    (
                        address_of(&call.target),
                        u256(&call.value),
                        bytes_of(&call.data),
                    )
                })
                .collect();
            let mut mode = B256::ZERO;
            mode.0[0] = 1;
            (mode, (batch,).abi_encode_params())
        }
    };
    let mut data = selector("execute(bytes32,bytes)").to_vec();
    data.extend((mode, Bytes::from(execution)).abi_encode_params());
    format!("0x{}", hex::encode(data))
}

fn word16(text: &str) -> [u8; 16] {
    u256(text).to_be_bytes::<32>()[16..]
        .try_into()
        .expect("sixteen bytes")
}

/// EntryPoint 0.9 `getUserOpHash`: EIP-712 over the packed operation.
fn user_operation_hash(chain_id: u64, entry_point: &str, op: &OwnerUserOperation) -> B256 {
    let text_hash = |text: &str| keccak256(text.as_bytes());
    let domain = keccak256(
        (
            text_hash(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            ),
            text_hash("ERC4337"),
            text_hash("1"),
            U256::from(chain_id),
            address_of(entry_point),
        )
            .abi_encode_params(),
    );
    let init_code = op.factory.as_ref().map_or_else(Vec::new, |factory| {
        [
            address_of(&factory.address).to_vec(),
            bytes_of(&factory.data).to_vec(),
        ]
        .concat()
    });
    let paymaster_and_data = op.paymaster.as_ref().map_or_else(Vec::new, |paymaster| {
        [
            address_of(&paymaster.address).to_vec(),
            word16(&paymaster.verification_gas_limit).to_vec(),
            word16(&paymaster.post_op_gas_limit).to_vec(),
            bytes_of(&paymaster.data).to_vec(),
        ]
        .concat()
    });
    let pair = |high: &str, low: &str| B256::from_slice(&[word16(high), word16(low)].concat());
    let struct_hash = keccak256(
        (
            text_hash(
                "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)",
            ),
            address_of(&op.sender),
            u256(&op.nonce),
            keccak256(init_code),
            keccak256(bytes_of(&op.call_data)),
            pair(&op.verification_gas_limit, &op.call_gas_limit),
            u256(&op.pre_verification_gas),
            pair(&op.max_priority_fee_per_gas, &op.max_fee_per_gas),
            keccak256(paymaster_and_data),
        )
            .abi_encode_params(),
    );
    keccak256([&[0x19, 0x01], domain.as_slice(), struct_hash.as_slice()].concat())
}

fn capture_request(value: &Value) -> ProtocolResult<OwnerOperationRequest> {
    let record = exact_record(
        value,
        &[
            "version",
            "kind",
            "account",
            "chainId",
            "entryPoint",
            "calls",
            "userOperation",
            "userOperationHash",
        ],
    )
    .or_fail(CODE)?;
    ensure(
        field(record, "version") == OWNER_OPERATION_REQUEST_VERSION
            && field(record, "kind") == "kernel-owner-operation",
        CODE,
    )?;
    let account = capture_kernel_account(field(record, "account"), CODE)?;
    let existing = match &account {
        KernelAccountProfile::Derived(profile) => {
            ensure(
                profile.factory_route == KernelFactoryRoute::KernelFactory,
                CODE,
            )?;
            false
        }
        KernelAccountProfile::Existing(profile) => {
            ensure(
                profile.kernel_version == KernelExistingAccountVersion::V0_4_0,
                CODE,
            )?;
            true
        }
    };
    let chain_id = safe_integer(field(record, "chainId"), 1, MAX_SAFE_INTEGER_U64).or_fail(CODE)?;
    let entry_point = address(field(record, "entryPoint"), false)?;
    let calls = capture_calls(field(record, "calls"))?;
    let user_operation = capture_user_operation(field(record, "userOperation"))?;
    // An existing account is already deployed: nothing may deploy it.
    ensure(!existing || user_operation.factory.is_none(), CODE)?;
    // Standard-mode root validation: the 192-bit key is only the uint16 lane.
    ensure(u256(&user_operation.nonce) >> 80 == U256::ZERO, CODE)?;
    ensure(user_operation.call_data == kernel_execution(&calls), CODE)?;
    let hash = hex_hash(user_operation_hash(chain_id, &entry_point, &user_operation));
    ensure(field(record, "userOperationHash") == hash.as_str(), CODE)?;
    Ok(OwnerOperationRequest {
        account,
        chain_id,
        entry_point,
        calls,
        user_operation,
        user_operation_hash: hash,
    })
}

pub fn parse_owner_operation_request(value: &Value) -> ProtocolResult<OwnerOperationRequest> {
    capture_request(value)
}

/// Captures a signed owner operation; the signature is shape-checked, not verified.
pub fn parse_signed_owner_operation(value: &Value) -> ProtocolResult<SignedOwnerOperation> {
    let record = exact_record(value, &["version", "request", "signature"]).or_fail(CODE)?;
    ensure(
        field(record, "version") == SIGNED_OWNER_OPERATION_VERSION,
        CODE,
    )?;
    let signature = bytes(field(record, "signature"), MAX_SIGNATURE_BYTES)?;
    ensure(signature != "0x", CODE)?;
    Ok(SignedOwnerOperation {
        request: capture_request(field(record, "request"))?,
        signature,
    })
}

/// `KernelFactory.deploy(initialPackages, index)` for the account's single root package.
fn factory_deploy(
    profile: &KernelDerivedAccountProfile,
    owner_validator: Option<&str>,
) -> ProtocolResult<String> {
    let (validator, module_data) = root_package(&profile.owner_credential, owner_validator)?;
    let packages = vec![(
        U256::from(1),
        validator,
        Bytes::from(module_data),
        Bytes::new(),
    )];
    let mut data = selector("deploy((uint256,address,bytes,bytes)[],uint256)").to_vec();
    data.extend((packages, u256(&profile.account_index)).abi_encode_params());
    Ok(format!("0x{}", hex::encode(data)))
}

/// Proves the request names the reviewed EntryPoint and its account: a
/// derived account's offline address and (while undeployed) its exact factory
/// deployment, or an existing account's own address with no factory.
/// `owner_validator` is the ECDSA root validator a derived account was derived
/// with, and `None` for P-256 and WebAuthn roots; an existing account's root is
/// proven on chain when it is imported, so it is not used.
pub fn verify_owner_operation_binding(
    request: &OwnerOperationRequest,
    owner_validator: Option<&str>,
) -> ProtocolResult<()> {
    ensure(request.entry_point == ENTRY_POINT_V09, BINDING)?;
    let profile = match &request.account {
        KernelAccountProfile::Existing(profile) => {
            return ensure(
                request.user_operation.sender == profile.address
                    && request.user_operation.factory.is_none(),
                BINDING,
            );
        }
        KernelAccountProfile::Derived(profile) => profile,
    };
    let sender = derive_kernel_v4_account_address(profile, owner_validator)
        .map_err(|_| crate::ProtocolError::new(BINDING))?;
    ensure(request.user_operation.sender == sender, BINDING)?;
    if let Some(factory) = &request.user_operation.factory {
        let data = factory_deploy(profile, owner_validator)
            .map_err(|_| crate::ProtocolError::new(BINDING))?;
        ensure(
            factory.address == KERNEL_V4_FACTORY && factory.data == data,
            BINDING,
        )?;
    }
    Ok(())
}

impl OwnerOperationRequest {
    pub fn owner_credential(&self) -> &OwnerCredentialProfile {
        self.account.owner_credential()
    }

    /// The digest the root signs.
    pub fn digest(&self) -> B256 {
        b256_of(&self.user_operation_hash)
    }

    pub fn to_json(&self) -> Value {
        let op = &self.user_operation;
        json!({
            "version": OWNER_OPERATION_REQUEST_VERSION,
            "kind": "kernel-owner-operation",
            "account": self.account.to_json(),
            "chainId": self.chain_id,
            "entryPoint": self.entry_point,
            "calls": self.calls.iter().map(|call| json!({
                "target": call.target,
                "value": call.value,
                "data": call.data,
            })).collect::<Vec<_>>(),
            "userOperation": {
                "sender": op.sender,
                "nonce": op.nonce,
                "callData": op.call_data,
                "callGasLimit": op.call_gas_limit,
                "verificationGasLimit": op.verification_gas_limit,
                "preVerificationGas": op.pre_verification_gas,
                "maxFeePerGas": op.max_fee_per_gas,
                "maxPriorityFeePerGas": op.max_priority_fee_per_gas,
                "factory": op.factory.as_ref().map(|factory| json!({
                    "address": factory.address,
                    "data": factory.data,
                })),
                "paymaster": op.paymaster.as_ref().map(|paymaster| json!({
                    "address": paymaster.address,
                    "verificationGasLimit": paymaster.verification_gas_limit,
                    "postOpGasLimit": paymaster.post_op_gas_limit,
                    "data": paymaster.data,
                })),
            },
            "userOperationHash": self.user_operation_hash,
        })
    }
}

impl SignedOwnerOperation {
    pub fn to_json(&self) -> Value {
        json!({
            "version": SIGNED_OWNER_OPERATION_VERSION,
            "request": self.request.to_json(),
            "signature": self.signature,
        })
    }
}
