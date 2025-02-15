/**
 * @file utils tests
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */

'use strict';
import { splitParamsString, b64tohex, hexStringToBase64 } from '../lib/Utils';
import { describe, assert, it } from 'vitest';

describe('Utils', function () {
   describe('#splitParamsString', function () {
      it('should split param strings', function () {
         const srcString =
            'N=4,s=K7YIn92KQeT9NfyZx7AYjw==,B=5axg064+LI3qRPuYDbJOgFHZ32OqLibrkDrLnL2pw3GDmoQ6lIPOLgUJjCmkrN35S+dXsFxMzXOLsZwz8JwojmjF+DwnRKCv+Uf49V378xvX7pg4hc=';
         const params = splitParamsString(srcString);

         assert.equal(params.N, '4');
         assert.equal(params.s, 'K7YIn92KQeT9NfyZx7AYjw==');
         assert.equal(
            params.B,
            '5axg064+LI3qRPuYDbJOgFHZ32OqLibrkDrLnL2pw3GDmoQ6lIPOLgUJjCmkrN35S+dXsFxMzXOLsZwz8JwojmjF+DwnRKCv+Uf49V378xvX7pg4hc=',
         );
      });
   });

   describe('b64 and hex conversion', () => {
      const b64 =
         '5axg064LI3qRPuYDbJOgFHZ32OqLibrkDrLnL2pw3GDmoQ6lIPOLgUJjCmkrN35SdXsFxMzXOLsZwz8JwojmjFDwnRKCvUf49V378xvX7pg4hQ==';
      const hex =
         'e5ac60d3ae0b237a913ee6036c93a0147677d8ea8b89bae40eb2e72f6a70dc60e6a10ea520f38b8142630a692b377e52757b05c4ccd738bb19c33f09c288e68c50f09d1282bd47f8f55dfbf31bd7ee983885';

      it('should convert to hex from base 64', () => {
         const hexOutput = b64tohex(b64);
         assert.equal(hexOutput, hex);
      });

      it('should convert to b64 from hex', () => {
         const b64Output = hexStringToBase64(hex);
         assert.equal(b64Output, b64);
      });
   });
});
