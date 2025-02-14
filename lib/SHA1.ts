

export async function sha1(str: string | Uint8Array) {
  let buffer: Uint8Array;

  if (typeof(str) == 'string') {
    const enc = new TextEncoder();
    buffer = enc.encode(str);
  }
  else  {
    buffer = str;
  }
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-1', buffer);
  return Array.from(new Uint8Array(hash))
    .map(v => v.toString(16).padStart(2, '0'))
    .join('');
}
