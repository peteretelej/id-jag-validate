// Base64url codec with tolerance for pasted tokens: embedded CRLF/whitespace
// and stray "=" padding are stripped before decoding; everything else is strict.

export function encode(input: Uint8Array<ArrayBuffer>): string {
  let binary = "";
  for (const byte of input) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decode(input: string): Uint8Array<ArrayBuffer> {
  const cleaned = input.replace(/[\r\n\t ]/g, "").replace(/=+$/, "");
  const b64 = cleaned.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function encodeUtf8(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>;
}

export function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
