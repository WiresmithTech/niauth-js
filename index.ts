/**
 * @file NIAuthenticator main
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */
'use strict';

import { base64ToByteArray } from './lib/Base64';
import { BigInteger, Client, ServerInfo } from './lib/SRP';
import {
   b64tohex,
   makeUrlBase64,
   bigIntToBase64,
   hexStringToBase64,
} from './lib/Utils';
import parseXML from 'xml-parse-from-string';

const getText = function (el) {
   return el.textContent || el.innerText || '';
};

class Prime {
   n: BigInteger;
   g: BigInteger;

   constructor(prime: { n: string; g: string }) {
      (this.n = new BigInteger(b64tohex(prime.n), 16)),
         (this.g = new BigInteger(b64tohex(prime.g), 16));
   }
}

/*
 * These are the 1024-bit primes and generators. We store them
 * as source as base64, but we need to transform them into a hex
 * string in order to turn them into BigIntegers.
 */
const primes = [
   {
      n: 'ieJUvpnjDnS8CjQLseVMV6+bLPH2bNQLFVj1nVgSrCdErkLGUGhosubcgk6I7XoqM417RFquVMZvqgXMwggvoJyvy003qXK1bukOLlW1cRW6KLCzRBljPsMG6WeNbKqAatVX1MDHtc/d35B4q2ZJ/UXDzFCE2H/MbbJH7yylr2c=',
      g: 'Cw==',
   },
   {
      n: '1XFmKuymyyba31KcEoWXHJco2eqggRxU9/ojMPPAkMaMRGw9WxIgEpfZGsxBOlY/ZciBaFWhbZd6gYK3AEYYEiW1N+noFDjBQyonPk3ZguElv9DgB8bv/bw9+U9o8DK1ScjJkrejEvoP2r9Bn6nANPd52l05digkV68v26fzb0c=',
      g: 'EQ==',
   },
   {
      n: 'iJWQ/xNLgaQM8A3XgQ4jmr4yOw4EQ8pcjQ2pJENouY9KfM5kjOGJdiOLnVYZqzDM6bk7wIVCBoO883dnWo4iXVvjsP1EPZ8fs9D2/u1bXtfcq7+ZWgvWGAmaiv9k2SAU8tq4W4ftseMg+CD1qtpGXylIxjWiR4GteZdgbFAS8Mc=',
      g: 'BQ==',
   },
   {
      n: '5axg064+LI3qRPuYNbgpjlEqoFLpA6VMdJfHs4kJGo74Cl2o4E5JXwkceD26WxT6PzwhHZeqpDbJOgFHZ32OqLibrkDrLnL2pw3GDmoQ6lIPOLgUJjCmkrN35S+dXsFxMzXOLsZwz8JwojmjF+DwnRKCv+Uf49V378xvX7pg4hc=',
      g: 'BQ==',
   },
   {
      n: 'oOFpUEn0CdvWkCF3heD/etjalOiuis53GgbgIaNbh6JTKiFgs5qN1PuKXBIGhtQ9tmxj+JiZAUMzV5AylidbB1YN/l1DMq/7YZoD1nySkDwF0YS3aJMt+Q4S5PzHuoDazCI//ZzCL8nDG565Aunbgx+kQgr37dsYSdDY8rdOOVc=',
      g: 'BQ==',
   },
].map(function (prime) {
   return new Prime(prime);
});

function hasSessionCookie() {
   return document.cookie.search('_appwebSessionId_') !== -1;
}

function getUserNameFromLoggedInString(str) {
   return str.match(/Logged in as: (.*)/)[1];
}

class Permission {
   name: string;
   builtin: boolean;
   id: number;

   constructor(xmlNode) {
      this.name = '';
      this.builtin = false;
      this.id = -1;

      for (let cn = 0; cn < xmlNode.childNodes.length; ++cn) {
         const cnode = xmlNode.childNodes[cn];
         if (cnode.tagName === 'Name') {
            this.name = getText(cnode);
         } else if (cnode.tagName === 'BuiltIn') {
            this.builtin = !!getText(cnode);
         } else if (cnode.tagName === 'ID') {
            this.id = parseInt(getText(cnode));
         }
      }
   }
}

type Permissions = { [key: string]: Permission };

function parsePermissions(xmlData): Permissions {
   const permissions = {};
   const root = xmlData.documentElement;
   if (root.tagName !== 'Permissions') {
      throw 'Unknown element type, got ' + root.tagName;
   }

   for (let cn = 0; cn < root.childNodes.length; ++cn) {
      const cnode = root.childNodes[cn];
      if (cnode.tagName === 'Permission') {
         const p = new Permission(cnode);
         permissions[p.name] = p;
      }
   }

   return permissions;
}

/*
 * Retrieve the user permissions for a user.
 */
export async function getAggregateUserPermissions(username) {
   let response = await fetch(
      '/LVWSAuthSvc/GetAggregateUserPermissions?username=' + (username || ''),
      {
         credentials: 'same-origin',
         method: 'GET',
         headers: { Accept: 'text/xml' },
      },
   );
   const text = await response.text();
   const xml = parseXML(text);
   return parsePermissions(xml);
}

const srpClient = new Client();
let loggedInUser = '';
let cachedPermissions: Permissions | undefined = undefined;

/*
 * This splits up a parameters string; as an example, the X-NI-AUTH-PARAMS
 * string has the format "N=4,s=[base64],B=[base64],ss=[base64]"
 */
function splitParamsString(str: string): { [key: string]: string } {
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

interface ServerHeaderParams {
   N: number;
   s: Uint8Array;
   B: BigInteger;
   ss: string;
}

/*
 * Decode the SRP parameters from the server.
 */
function decodeServerParamsString(srpParams: string): ServerInfo {
   const paramStrings = splitParamsString(srpParams);
   if (
      !paramStrings.hasOwnProperty('N') ||
      !paramStrings.hasOwnProperty('s') ||
      !paramStrings.hasOwnProperty('B') ||
      !paramStrings.hasOwnProperty('ss')
   ) {
      throw "didn't get everything we needed from server";
   }

   const params: ServerHeaderParams = {
      N: parseInt(paramStrings.N, 10),
      s: base64ToByteArray(paramStrings.s),
      B: new BigInteger(b64tohex(paramStrings.B), 16),
      ss: paramStrings.ss,
   };

   if (params.N > primes.length) {
      throw 'invalid prime index';
   }

   return {
      modulus: primes[params.N].n,
      generator: primes[params.N].g,
      salt: params.s,
      publicKey: params.B,
      // We don't need to operate on the login token, so leave as string.
      loginToken: params.ss,
   };
}

// eslint-disable-next-line no-unused-consts
async function updatePermissionsCache() {
   let permissions = await getAggregateUserPermissions(loggedInUser);
   cachedPermissions = permissions;
}

export function getUserName() {
   return loggedInUser;
}

/*
 * This is used to synchronize the client state with the server state;
 * specifically, if we have a session cookie, we want to figure out if
 * that cookie is for a valid session.
 *
 * @returns {Promise} true if logged in, false if logged out
 */
export async function updateFromSession(): Promise<boolean> {
   if (!hasSessionCookie()) {
      /* We don't have a session cookie on our end. */
      return false;
   }

   let response = await fetch('/Login', {
      credentials: 'same-origin',
      method: 'GET',
   });

   if (response.status === 200) {
      /*
       * The response text is a plain text string:
       * "Logged in as: username"
       */
      let text = await response.text();
      loggedInUser = getUserNameFromLoggedInString(text);
      await updatePermissionsCache();

      return true;
   } else {
      /*
       * For any other error, assume that the session is bad or
       * expired.
       */
      return false;
   }
}

/*
 * Log in to NIAuth.
 *
 * @returns {Promise} will resolve to true if successful
 */
export async function login(username, password): Promise<boolean> {
   /* Configure the SRP client. */
   srpClient.setIdentity({ username: username, password: password });

   /*
    * Issue the initial login request.
    */
   let response = await fetch('/Login?username=' + (username || ''), {
      credentials: 'same-origin',
      method: 'GET',
   });

   if (response.status === 200) {
      /*
       * If we get a 200, we have a valid session cookie and we're
       * already logged in. The response text is a plain text string:
       * "Logged in as: username"
       * We need to make sure it matches.
       */
      let text = await response.text();
      loggedInUser = getUserNameFromLoggedInString(text);

      if (loggedInUser === username) {
         /* Excellent. Update permissions. */
         await updatePermissionsCache();
      } else {
         /* TODO: This can and should be handled by automatically logging out. */
         throw 'Already logged in as ' + loggedInUser + ', log out first!';
      }
      return true;
   } else if (response.status === 403) {
      /*
       * A 403 is "expected" on a fresh login. It's how we obtain the
       * X-NI-AUTH-PARAMS header containing information for the next
       * part of the SRP handshake.
       */

      /* Obtain the SRP parameters */
      const serverParams = response.headers.get('X-NI-AUTH-PARAMS');
      if (!serverParams) {
         throw 'No auth parameters from server';
      }
      return await newLogin(serverParams);
   } else {
      throw (
         'Unknown/unhandled status code from NIAuth (' + response.status + ')'
      );
   }
}

async function newLogin(serverParams: string): Promise<boolean> {
   const serverInfo = decodeServerParamsString(serverParams);

   /* Generate the client-side parameters */
   srpClient.setServerInfo(serverInfo);
   const clientParams = await srpClient.generatePublicKeyAndProof();

   /* Send the client-side parameters back to the server */
   let data =
      'A=' + makeUrlBase64(bigIntToBase64(clientParams.clientPublicKey, 128));
   data += '&M=' + makeUrlBase64(hexStringToBase64(clientParams.clientProof));
   data += '&ss=' + serverInfo.loginToken;

   const authResponse = await fetch('/Login', {
      credentials: 'same-origin',
      method: 'POST',
      headers: {
         'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: data,
   });

   if (authResponse.status === 200) {
      const text = await authResponse.text();
      loggedInUser = getUserNameFromLoggedInString(text);
      await updatePermissionsCache();
      return true;
   } else {
      return false;
   }
}

/*
 * Logs out of NI Auth. This clears the session.
 *
 * @returns {Promise} will resolve to true if successful
 */
export async function logout() {
   if (!hasSessionCookie()) {
      /*
       * If we don't have the session cookie, then we don't have a session.
       * Ergo, we are already logged out.
       */
      loggedInUser = '';
      return true;
   }

   let response = await fetch('/Logout', {
      credentials: 'same-origin',
      method: 'GET',
   });

   if (response.ok) {
      return true;
   } else {
      return false;
   }
}

/*
 * Does the currently logged-in user have permission for something?
 */
export function hasPermission(permName: string): boolean {
   if (cachedPermissions === undefined) {
      return false;
   }
   return cachedPermissions.hasOwnProperty(permName);
}
