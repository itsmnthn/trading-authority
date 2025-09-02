/**
 * @file Reusable utility functions for creating a Trading Authority key from
 * an EIP-712 signature. This module is framework-agnostic and can be used in
 * any JavaScript project.
 *
 * @requires viem
 * @requires @scure/bip32
 * @requires @scure/bip39
 */

import { HDKey } from '@scure/bip32';
import { entropyToMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { keccak256, toBytes, toHex } from 'viem';

/**
 * Common constants used across the Trading Authority helpers.
*/
// First account (standard path)
export const ETH_DERIVATION_PATH = "m/44'/60'/0'/0/0"; 
export const DEFAULT_PRIMARY_TYPE = 'authority';
export const DEFAULT_MESSAGE_TEMPLATE = Object.freeze({
    action: 'Authority creation/recreation',
    notice:
        'Only sign this on ta.itsmnthn.dev to generate a authority key.'
});

/**
 * Tiny assertion helper for clearer error messages.
 * @param {unknown} condition
 * @param {string} message
 */
function assert(condition, message) {
    if (!condition) throw new Error(message);
}

/**
 * Derives a mnemonic phrase and a private key from a given 32-byte entropy
 * source. This is a pure function that uses BIP-39 and BIP-32 standards.
 *
 * @param {Uint8Array} entropy - A 32-byte Uint8Array to be used as the source
 * for key generation.
 * @returns {{mnemonic: string, privateKey: `0x${string}`}} An object
 * containing the derived mnemonic and private key.
 * @throws {Error} if a private key cannot be derived.
 */
export function exportMnemonicAndPrivateKey(entropy) {
    assert(entropy instanceof Uint8Array, 'Entropy must be a Uint8Array');
    assert(entropy.length === 32, 'Entropy must be exactly 32 bytes');

    const mnemonic = entropyToMnemonic(entropy, wordlist);
    const seed = mnemonicToSeedSync(mnemonic);
    const hdKey = HDKey.fromMasterSeed(seed);

    const derivedKey = hdKey.derive(ETH_DERIVATION_PATH);
    assert(
        !!derivedKey.privateKey,
        'Could not derive private key from master seed.'
    );

    return {
        mnemonic,
        privateKey: toHex(derivedKey.privateKey)
    };
}

/**
 * Deterministically derives a Trading Authority (mnemonic and private key)
 * from a 65-byte Ethereum signature. It uses the `r` and `s` components of
 * the signature as a unique source of entropy.
 *
 * @param {`0x${string}`} signature - The 65-byte signature hex string
 * (`0x...`).
 * @returns {{mnemonic: string, privateKey: `0x${string}`}} The derived
 * mnemonic and private key.
 * @throws {Error} if the signature is not 65 bytes long.
 */
export function deriveHDKeyFromEthereumSignature(signature) {
    const signatureBytes = toBytes(signature);
    assert(signatureBytes.length === 65, 'Signature must be 65 bytes long');

    // The first 64 bytes of a signature are the `r` and `s` values. `v` is the
    // last byte.
    const rAndS = signatureBytes.subarray(0, 64);
    // Hash r+s → 32-byte entropy (required by BIP-39)
    const entropy = toBytes(keccak256(rAndS));
    return exportMnemonicAndPrivateKey(entropy);
}

/**
 * Convenience helper: compute 32-byte entropy directly from a signature.
 * Exported for testing and advanced usage.
 * @param {`0x${string}`} signature
 * @returns {Uint8Array}
 */
export function entropyFromSignature(signature) {
    const signatureBytes = toBytes(signature);
    assert(signatureBytes.length === 65, 'Signature must be 65 bytes long');
    const rAndS = signatureBytes.subarray(0, 64);
    return toBytes(keccak256(rAndS));
}

/**
 * Generates the full EIP-712 typed data structure required for the user to
 * sign.
 *
 * @param {object} options - The options for creating the typed data.
 * @param {object} options.domain - The EIP-712 domain separator (e.g.,
 * { name: 'MyDApp', version: '1' }).
 * @param {number} options.chainId - The chain ID for the signature.
 * @param {number} options.nonce - The nonce for this specific signature, to
 * prevent replays and allow for multiple authorities.
 * @returns {object} The complete EIP-712 typed data object for `viem`.
 */
export function getTypedDataForSignature({
    domain,
    chainId,
    nonce,
    primaryType = DEFAULT_PRIMARY_TYPE,
    messageOverrides = {}
}) {
    assert(domain && typeof domain === 'object', 'domain must be provided');
    assert(
        typeof domain.name === 'string' && domain.name.length > 0,
        'domain.name must be a non-empty string'
    );
    assert(
        typeof domain.version === 'string' && domain.version.length > 0,
        'domain.version must be a non-empty string'
    );
    assert(
        Number.isInteger(chainId) && chainId > 0,
        'chainId must be a positive integer'
    );
    assert(
        Number.isInteger(nonce) && nonce >= 0,
        'nonce must be a non-negative integer'
    );

    const types = {
        [primaryType]: [
            { name: 'action', type: 'string' },
            { name: 'notice', type: 'string' },
            { name: 'chainId', type: 'string' },
            { name: 'nonce', type: 'uint256' }
        ],
        EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' }
        ]
    };

    const message = {
        ...DEFAULT_MESSAGE_TEMPLATE,
        chainId: String(chainId),
        nonce,
        ...messageOverrides
    };

    const typedData = {
        types,
        primaryType,
        domain: { ...domain, chainId },
        message
    };

    return Object.freeze(typedData);
}

/**
 * The main exported function to generate a new Trading Authority. It
 * orchestrates the process of creating typed data, requesting a signature,
 * and deriving the key.
 *
 * @param {import('viem').WalletClient} walletClient - An active `viem`
 * WalletClient instance (e.g., from `createWalletClient`).
 * @param {object} options - The options for generating the authority.
 * @param {`0x${string}`} options.account - The user's wallet address
 * (`0x...`) that will sign the message.
 * @param {object} options.domain - The EIP-712 domain (e.g.,
 * { name: 'MyDApp', version: '1' }).
 * @param {number} options.chainId - The chain ID where the signature is
 * valid.
 * @param {number} options.nonce - The nonce for this authority creation.
 * @returns {Promise<{mnemonic: string, privateKey: `0x${string}`}>} A
 * promise that resolves to the new Trading Authority's mnemonic and private
 * key.
 */
export async function generateTradingAuthority(
    walletClient,
    {
        account,
        domain,
        chainId,
        nonce,
        primaryType,
        messageOverrides
    } = {}
) {
    assert(!!walletClient, 'walletClient is required');
    assert(!!account, 'account is required');
    assert(!!domain, 'domain is required');
    assert(chainId !== undefined, 'chainId is required');
    assert(nonce !== undefined, 'nonce is required');

    const typedData = getTypedDataForSignature({
        domain,
        chainId,
        nonce,
        primaryType,
        messageOverrides
    });

    let signature;
    try {
        signature = await walletClient.signTypedData({
            account,
            ...typedData
        });
    } catch (error) {
        throw new Error(
            `Failed to obtain signature: ${error?.message || String(error)}`
        );
    }

    try {
        return deriveHDKeyFromEthereumSignature(signature);
    } catch (error) {
        throw new Error(
            `Failed to derive authority from signature: ${error?.message || String(error)
            }`
        );
    }
}
