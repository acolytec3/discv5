import * as secp from "@noble/secp256k1";
import { AbstractKeypair, IKeypair, IKeypairClass, KeypairType } from "./types";
import { ERR_INVALID_KEYPAIR_TYPE } from "./constants";

export const Secp256k1Keypair: IKeypairClass = class Secp256k1Keypair extends AbstractKeypair implements IKeypair {
  readonly type: KeypairType;

  constructor(privateKey?: Buffer, publicKey?: Buffer) {
    super(privateKey, publicKey);
    this.type = KeypairType.secp256k1;
  }

  static generate(): Secp256k1Keypair {
    const privateKey = secp.utils.randomPrivateKey();
    const publicKey = secp.getPublicKey(privateKey);
    return new Secp256k1Keypair(Buffer.from(privateKey), Buffer.from(publicKey));
  }

  privateKeyVerify(key = this._privateKey): boolean {
    if (key) {
      return secp.utils.isValidPrivateKey(secp.utils.bytesToHex(Uint8Array.from(key)));
    }
    return true;
  }

  sign(msg: Buffer): Buffer {
    return Buffer.from(secp.sign(secp.utils.bytesToHex(Uint8Array.from(msg)), this.privateKey));
  }

  verify(msg: Buffer, sig: Buffer): boolean {
    return secp.verify(
      secp.utils.bytesToHex(Uint8Array.from(sig)),
      secp.utils.bytesToHex(Uint8Array.from(msg)),
      this.publicKey
    );
  }

  deriveSecret(keypair: IKeypair): Buffer {
    if (keypair.type !== this.type) {
      throw new Error(ERR_INVALID_KEYPAIR_TYPE);
    }
    const secret = Buffer.from(
      secp.getSharedSecret(
        secp.utils.bytesToHex(Uint8Array.from(this.privateKey)),
        secp.utils.bytesToHex(Uint8Array.from(keypair.publicKey))
      )
    );
    return secret;
  }
};
