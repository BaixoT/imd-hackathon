// Contract-creation code that deploys `runtime` verbatim as a contract's code (no constructor logic).
//   PUSH3 len | DUP1 | PUSH1 0x0b | PUSH0 | CODECOPY | PUSH0 | RETURN | runtime
// Used to publish the 20,545-byte prepared key blob (leading 0x00 byte keeps it non-executable
// and EIP-3541 compatible). Pure and import-free so the Foundry FFI tests (blockchain/test/ffi) run the exact function used by the UI.
export function blobInitCode(runtimeHex: string): string {
  const body = runtimeHex.replace(/^0x/, '')
  if (body.length % 2 || !/^[0-9a-fA-F]*$/.test(body)) throw new Error('Blob must be hex bytes.')
  const length = body.length / 2
  if (length === 0 || length > 0xffffff) throw new Error('Unsupported blob length.')
  return '0x62' + length.toString(16).padStart(6, '0') + '80600b5f395ff3' + body
}
