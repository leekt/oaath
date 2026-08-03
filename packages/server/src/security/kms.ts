/**
 * Deployment-owned encryption port.
 *
 * The relay stores only the opaque reference this port returns. It never sees a
 * key, and plaintext never reaches the store.
 *
 * @author taek <leekt216@gmail.com>
 */

export interface RelayKms {
  /** Resolves to an opaque bounded string reference for the ciphertext. */
  encrypt(plaintext: string): Promise<unknown>;
  /** Resolves to the plaintext for a reference this port previously returned. */
  decrypt(ciphertextRef: string): Promise<unknown>;
}
