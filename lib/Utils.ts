/**
 * @file uncategorized utilities
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */

import { base64ToByteArray, byteArrayToBase64 } from './Base64';

/**
 * Transform a "hash string" into a byte array.
 */
export function HashStringToByteArray(str: string): Uint8Array {
   const ar: number[] = [];
   for (let i = 0; i < str.length; i += 2) {
      ar.push(parseInt(str.substr(i, 2), 16));
   }
   return new Uint8Array(ar);
}

/**
 * Transform a byte array into a "hash string".
 */
export function byteArrayToHashString(ar: Uint8Array): string {
   let hs = '';
   for (let i = 0; i < ar.length; ++i) {
      hs += ('00' + (ar[i] & 0xff).toString(16)).substr(-2);
   }
   return hs;
}


function numberToHex(num: number): string {
   return num.toString(16).padStart(2, '0');
}

export function b64tohex(b64str: string): string {
   const bytes = base64ToByteArray(b64str);
   let output = '';
   for (const byte of bytes) {
      output += numberToHex(byte);
   }
   return output;
}

export function hexStringToBase64(str: string): string {
   const bytes: number[] = [];
   for (let i = 0; i < str.length; i += 2) {
      bytes.push(parseInt(str.substr(i, 2), 16));
   }
   return byteArrayToBase64(new Uint8Array(bytes));
}



/* XOR two hash strings.
 * Example:
 *   "a7a9e7e59519897d" ^ "30a85174187253d3"
 * Assumes hashes are a multiple of 4 characters long.
 *
 * @param {hex string} a
 * @param {hex string} b
 * @returns {hex string} a xor b
 */
export function xorHashStrings(a: string, b: string): string {
   if (a.length !== b.length) {
      throw 'strings not same length';
   }

   let res = '';

   /* four chars at a time === 16-bit chunks */
   /* this avoids problems with negative overflow that we'd have with 32-bit */
   for (let i = 0; i < a.length; i += 4) {
      const ac = parseInt(a.substr(i, 4), 16);
      const bc = parseInt(b.substr(i, 4), 16);
      res += ('0000' + (ac ^ bc).toString(16)).substr(-4);
   }
   return res;
}

/**
 * Turn a regular Base64-encoded string into a URL-Base64-encoded string.
 *
 * This works by turning char 62 from "+" to "-" and char 63 from "/" to "_".
 *
 * @param {String} regularBase64Str
 */
export function makeUrlBase64(regularBase64Str: string): string {
   let newStr = '';
   for (let i = 0; i < regularBase64Str.length; ++i) {
      if (regularBase64Str.charAt(i) === '+') {
         newStr += '-';
      } else if (regularBase64Str.charAt(i) === '/') {
         newStr += '_';
      } else {
         newStr += regularBase64Str.charAt(i);
      }
   }
   return newStr;
}

/*
 * This splits up a parameters string; as an example, the X-NI-AUTH-PARAMS
 * string has the format "N=4,s=[base64],B=[base64],ss=[base64]"
 */
export function splitParamsString(str: string): { [key: string]: string } {
   const ret = {};
   const params = str.split(',');
   for (let i = 0; i < params.length; ++i) {
      const equals = params[i].indexOf('=');
      if (equals === -1) {
         throw 'not a valid params string';
      }

      const name = params[i].substr(0, equals);
      const value = params[i].substr(equals + 1);

      ret[name] = value;
   }
   return ret;
}
