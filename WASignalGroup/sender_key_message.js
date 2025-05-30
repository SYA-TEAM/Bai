const CiphertextMessage = require('./ciphertext_message');
const curve = require('libsignal/src/curve');
const protobufs = require('./protobufs');

class SenderKeyMessage extends CiphertextMessage {
  SIGNATURE_LENGTH = 64;
  CURRENT_VERSION = 3;

  constructor(
    keyId = null,
    iteration = null,
    ciphertext = null,
    signatureKey = null,
    serialized = null
  ) {
    super();

    if (serialized) {
      const version = serialized[0];
      const message = serialized.slice(1, serialized.length - this.SIGNATURE_LENGTH);
      const signature = serialized.slice(-1 * this.SIGNATURE_LENGTH);
      const senderKeyMessage = protobufs.SenderKeyMessage.decode(message).toJSON();
      senderKeyMessage.ciphertext = Buffer.from(senderKeyMessage.ciphertext, 'base64');

      this.serialized = serialized;
      this.messageVersion = (version & 0xff) >> 4;
      this.keyId = senderKeyMessage.id;
      this.iteration = senderKeyMessage.iteration;
      this.ciphertext = senderKeyMessage.ciphertext;
      this.signature = signature;
    } else if (keyId && iteration !== null && ciphertext && signatureKey) {
      
      const version = (((this.CURRENT_VERSION << 4) | this.CURRENT_VERSION) & 0xff) % 256;
      const ciphertextBuffer = Buffer.from(ciphertext);

      const message = protobufs.SenderKeyMessage.encode(
        protobufs.SenderKeyMessage.create({
          id: keyId,
          iteration,
          ciphertext: ciphertextBuffer
        })
      ).finish();

      const serializedPayload = Buffer.concat([Buffer.from([version]), message]);

      const signature = Buffer.from(
        curve.calculateSignatureSync
          ? curve.calculateSignatureSync(signatureKey, serializedPayload)
          : curve.calculateSignature(signatureKey, serializedPayload)
      );

      this.serialized = Buffer.concat([serializedPayload, signature]);
      this.keyId = keyId;
      this.iteration = iteration;
      this.ciphertext = ciphertextBuffer;
      this.signature = signature;
      this.messageVersion = this.CURRENT_VERSION;
    } else {
      throw new Error("Invalid arguments for SenderKeyMessage constructor.");
    }
  }

  static async create(keyId, iteration, ciphertext, signatureKey) {
    const version = (((this.prototype.CURRENT_VERSION << 4) | this.prototype.CURRENT_VERSION) & 0xff) % 256;
    const ciphertextBuffer = Buffer.from(ciphertext);

    const message = protobufs.SenderKeyMessage.encode(
      protobufs.SenderKeyMessage.create({
        id: keyId,
        iteration,
        ciphertext: ciphertextBuffer
      })
    ).finish();

    const serializedPayload = Buffer.concat([Buffer.from([version]), message]);

    const signature = await this.prototype.getSignature(signatureKey, serializedPayload);

    const serialized = Buffer.concat([serializedPayload, Buffer.from(signature)]);

    return new SenderKeyMessage(null, null, null, null, serialized);
  }

  getKeyId() {
    return this.keyId;
  }

  getIteration() {
    return this.iteration;
  }

  getCipherText() {
    return this.ciphertext;
  }

  verifySignature(signatureKey) {
    const part1 = this.serialized.slice(0, this.serialized.length - this.SIGNATURE_LENGTH);
    const part2 = this.serialized.slice(-1 * this.SIGNATURE_LENGTH);
    const res = curve.verifySignature(signatureKey, part1, part2);
    if (!res) throw new Error('Invalid signature!');
  }

  async getSignature(signatureKey, serialized) {
    const sig = curve.calculateSignature
      ? await curve.calculateSignature(signatureKey, serialized)
      : curve.calculateSignatureSync(signatureKey, serialized);
    return Buffer.from(sig);
  }

  serialize() {
    return this.serialized;
  }

  getType() {
    return 4;
  }
}

module.exports = SenderKeyMessage;
