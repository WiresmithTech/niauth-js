/**
 * @file base64 encode/decode wrappers
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */
/*
* Convert the byte array to base 64. 
* This is a feature being added to the base language but currently
* isn't supported in chrome or edge.
*/
export function byteArrayToBase64(array: Uint8Array): string {
   const bytes_string = String.fromCharCode(...array.values());
   return window.btoa(bytes_string);
}


/*
* Convert a base64 string to a byte array.
* This is now supported on the UInt8Array type but that
* isn't avaialble in edge or chrome yet.
*/
export function base64ToByteArray(string: string): Uint8Array {
   var decoded = window.atob(string); 
   const bytes = new Uint8Array(decoded.split("").map((c: string): number => c.charCodeAt(0)));
   return bytes;
}