import { Sha1 } from '@aws-crypto/sha1-browser';
import { byteArrayToHashString } from './Utils';

export async function sha1(str: string | Uint8Array): Promise<string> {
   const hasher = new Sha1();

   if (typeof str === 'string') {
      hasher.update(str);
   } else {
      hasher.update(str);
   }

   const hash = await hasher.digest();
   return byteArrayToHashString(hash);
}
