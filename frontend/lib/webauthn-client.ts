/**
 * Duenner Wrapper um die native `navigator.credentials` WebAuthn-API.
 * Bewusst ohne zusaetzliche npm-Library -- der Browser bringt alles
 * Notwendige schon mit, wir muessen nur zwischen base64url (das Backend
 * schickt/erwartet Strings) und ArrayBuffer (das der Browser braucht)
 * konvertieren.
 */

function base64urlToBuffer(base64url: string): ArrayBuffer {
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const buffer = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buffer[i] = raw.charCodeAt(i);
  return buffer.buffer;
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function isWebAuthnSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential;
}

/** Registriert einen neuen Passkey. `optionsJson` kommt 1:1 vom Backend. */
export async function registerPasskey(optionsJson: string): Promise<object> {
  const options = JSON.parse(optionsJson);

  const publicKey: CredentialCreationOptions["publicKey"] = {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: { ...options.user, id: base64urlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials ?? []).map((c: { id: string }) => ({
      ...c,
      id: base64urlToBuffer(c.id),
    })),
  };

  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      transports: response.getTransports ? response.getTransports() : [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

/** Loest eine bestehende Passkey-Anmeldung aus. */
export async function authenticateWithPasskey(optionsJson: string): Promise<object> {
  const options = JSON.parse(optionsJson);

  const publicKey: CredentialRequestOptions["publicKey"] = {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((c: { id: string }) => ({
      ...c,
      id: base64urlToBuffer(c.id),
    })),
  };

  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}
