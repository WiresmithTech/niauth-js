import { byteArrayToBase64 } from "./Base64";
import { b64tohex, byteArrayToHashString, HashStringToByteArray } from "./Utils";

export function bigIntFromHex(hex: string): bigint {
  return BigInt('0x' + hex);
}

export function bigIntToHex(ba: bigint): string {
  let string = ba.toString(16);
  // Introduce leading 0 if needed.
  if (string.length % 2 !== 0) {
    string = '0' + string;
  }
  return string;
}

export function bigIntFromBase64(b64: string): bigint {
  const hex = b64tohex(b64);
  return bigIntFromHex(hex);
}

export function bigIntToBase64(ba: bigint, len: number): string {
  const bytes = bigIntegerToBytes(ba, len);
  return byteArrayToBase64(bytes);
}

export function bigIntFromByteArray(array: Uint8Array): bigint {
  return bigIntFromHex(byteArrayToHashString(array));
}

export function randomBigInt(bits: number): bigint {
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  crypto.getRandomValues(bytes);
  return bigIntFromByteArray(bytes);
}


// jsbn's bigint doesn't give all the bytes we expect all the time...
export function bigIntegerToBytes(
  bi: bigint,
  byteCount: number,
): Uint8Array {
  let bigIntStr = bigIntToHex(bi);
  const bytes = HashStringToByteArray(bigIntStr);
  const actualByteLength = bytes.length;

  if (actualByteLength === byteCount) {
    return new Uint8Array(bytes);
  } else if (actualByteLength < byteCount) {
    // left-pad with zeroes
    const paddingBytes = byteCount - bytes.length;
    const na = new Uint8Array(paddingBytes).fill(0);
    const padded = new Uint8Array([...na, ...bytes]);
    return padded;
  } else if (actualByteLength > byteCount) {
    // trim leading zeroes
    const leaders = bytes.slice(0, bytes.length - byteCount);
    for (let i = 0; i < leaders.length; ++i) {
      if (leaders[i] !== 0) {
        throw 'attmpted to truncate to ' + byteCount;
      }
    }
    return new Uint8Array(bytes.slice(bytes.length - byteCount));
  } else {
    throw 'unreachable';
  }
}
