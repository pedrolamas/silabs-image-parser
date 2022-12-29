import assert from 'assert';
import crc32 from 'buffer-crc32';

const validSilabsCrc32 = <const>0x2144df1c;

const gblTagHeader = <const>0x03a617eb;
const gblTagApplication = <const>0xf40a0af4;
const gblTagBootloader = <const>0xf50909f5;
const gblTagSeUpgrade = <const>0x5ea617eb;
const gblTagMetadata = <const>0xf60808f6;
const gblTagProg = <const>0xfe0101fe;
const gblTagEraseProg = <const>0xfd0303fd;
const gblTagEnd = <const>0xfc0404fc;

const gblTagEncHeader = <const>0xfb0505fb;
const gblTagEncInit = <const>0xfa0606fa;
const gblTagEncEblData = <const>0xf90707f9;
const gblTagEncMac = <const>0xf70909f7;
const gblTagSignatureEcdsaP256 = <const>0xf70a0af7;
const gblTagCertificateEcdsaP256 = <const>0xf30b0bf3;

type ApplicationData = {
  type: number;
  version: number;
  capabilities: number;
  productId: Buffer;
};

type ApplicationCertificate = {
  structVersion: number;
  flags: Buffer;
  key: Buffer;
  version: number;
  signature: Buffer;
};

type GblTagBase<T> = {
  tag: T;
  len: number;
};

type GblHeader = GblTagBase<typeof gblTagHeader> & {
  version: number;
  type: number;
};

type GblApplicationElement = GblTagBase<typeof gblTagApplication> & {
  applicationData: ApplicationData;
};

type GblBootloaderElement = GblTagBase<typeof gblTagBootloader> & {
  bootloaderVersion: number;
  address: number;
  data: Buffer;
};

type GblSeUpgradeElement = GblTagBase<typeof gblTagSeUpgrade> & {
  blobSize: number;
  version: number;
  data: Buffer;
};

type GblMetadataElement = GblTagBase<typeof gblTagMetadata> & {
  metaData: Buffer;
};

type GblProgElement = GblTagBase<typeof gblTagProg | typeof gblTagEraseProg> & {
  flashStartAddress: number;
  data: Buffer;
};

type GblEndElement = GblTagBase<typeof gblTagEnd> & {
  eblCrc: number;
};

type GblEncryptionHeaderElement = GblTagBase<typeof gblTagEncHeader> & {
  version: number;
  magicWord: number;
  encryptionType: number;
};

type GblEncryptionInitAesCcmElement = GblTagBase<typeof gblTagEncInit> & {
  msgLen: number;
  nouce: Buffer;
};

type GblEncryptionDataElement = GblTagBase<typeof gblTagEncEblData> & {
  encryptedEblData: Buffer;
};

type GblTagEncryptionAesCcmSignatureElement = GblTagBase<typeof gblTagEncMac> & {
  eblMac: Buffer;
};

type GblCertificateEcdsaP256Element = GblTagBase<typeof gblTagCertificateEcdsaP256> & {
  applicationCertificate: ApplicationCertificate;
};

type GblSignatureEcdsaP256Element = GblTagBase<typeof gblTagSignatureEcdsaP256> & {
  r: Buffer;
  s: Buffer;
};

type GblElement = GblApplicationElement | GblBootloaderElement | GblSeUpgradeElement | GblMetadataElement | GblProgElement | GblEndElement | GblEncryptionHeaderElement | GblEncryptionInitAesCcmElement | GblEncryptionDataElement | GblTagEncryptionAesCcmSignatureElement | GblCertificateEcdsaP256Element | GblSignatureEcdsaP256Element;

type GblData = {
  header: GblHeader;
  elements: GblElement[];
};

const isValid = (buffer: Buffer): boolean => {
  if (buffer.length < 10) {
    return false;
  }

  const tag = buffer.readUInt32LE();

  return tag === gblTagHeader;
};

const parse = (buffer: Buffer): GblData => {
  const header = parseGblHeader(buffer);

  let position = 8 + header.len;
  const elements = [];
  while (position < buffer.length) {
    const element = parseGblSubElement(buffer, position);

    elements.push(element);

    position += 8 + element.len;

    if (element.tag === gblTagEnd) {
      break;
    }
  }

  const calculatedCrc32 = crc32.unsigned(buffer.slice(0, position));

  assert.strictEqual(calculatedCrc32, validSilabsCrc32, `Image CRC-32 is invalid`);

  return {
    header,
    elements,
  };
};

const parseGblHeader = (buffer: Buffer): GblHeader => {
  const tag = buffer.readUInt32LE();

  assert.strictEqual(tag, gblTagHeader, `Unknown header tag`);

  return {
    tag,
    len: buffer.readUInt32LE(4),
    version: buffer.readUInt32BE(8),
    type: buffer.readUInt32BE(12),
  };
};

const parseGblSubElement = (data: Buffer, position: number): GblElement => {
  const tag = data.readUInt32LE(position);
  const len = data.readUInt32LE(position + 4);

  switch (tag) {
    case gblTagApplication:
      return {
        tag,
        len,
        applicationData: {
          type: data.readUInt32BE(position + 8),
          version: data.readUInt32BE(position + 12),
          capabilities: data.readUInt32BE(position + 16),
          productId: data.slice(position + 20, position + 8 + len),
        },
      };

    case gblTagBootloader:
      return {
        tag,
        len,
        bootloaderVersion: data.readUInt32BE(position + 8),
        address: data.readUInt32BE(position + 12),
        data: data.slice(position + 16, position + 8 + len),
      };

    case gblTagSeUpgrade:
      return {
        tag,
        len,
        blobSize: data.readUInt32BE(position + 8),
        version: data.readUInt32BE(position + 12),
        data: data.slice(position + 16, position + 8 + len),
      };

    case gblTagMetadata:
      return {
        tag,
        len,
        metaData: data.slice(position + 8, position + 8 + len),
      };

    case gblTagProg:
    case gblTagEraseProg:
      return {
        tag,
        len,
        flashStartAddress: data.readUInt32BE(position + 8),
        data: data.slice(position + 12, position + 8 + len),
      };

    case gblTagEnd:
      assert.ok(len === 4, `End subelement length should be 4, but was ${len}`);

      return {
        tag,
        len,
        eblCrc: data.readUInt32BE(position + 8),
      };

    case gblTagEncHeader:
      assert.ok(len === 12, `Encryption header subelement length should be 12, but was ${len}`);

      return {
        tag,
        len,
        version: data.readUInt32BE(position + 8),
        magicWord: data.readUInt32BE(position + 12),
        encryptionType: data.readUInt32BE(position + 16),
      };

    case gblTagEncInit:
      assert.ok(len === 16, `Encryption init subelement length should be 16, but was ${len}`);

      return {
        tag,
        len,
        msgLen: data.readUInt32BE(position + 8),
        nouce: data.slice(position + 12, position + 24),
      };

    case gblTagEncEblData:
      return {
        tag,
        len,
        encryptedEblData: data.slice(position + 8, position + 8 + len),
      };

    case gblTagEncMac:
      assert.ok(len === 16, `Encryption AES-CCM MAC subelement length should be 16, but was ${len}`);

      return {
        tag,
        len,
        eblMac: data.slice(position + 8, position + 24),
      };

    case gblTagCertificateEcdsaP256:
      return {
        tag,
        len,
        applicationCertificate: {
          structVersion: data.readInt8(position + 8),
          flags: data.slice(position + 9, position + 13),
          key: data.slice(position + 13, position + 77),
          version: data.readUInt32BE(position + 77),
          signature: data.slice(position + 81, position + 81 + 145),
        },
      };

    case gblTagSignatureEcdsaP256:
      assert.ok(len === 64, `ECDSA secp256r1 signature subelement length should be 64, but was ${len}`);

      return {
        tag,
        len,
        r: data.slice(position + 8, position + 40),
        s: data.slice(position + 40, position + 72),
      };

    default:
      throw new Error(`Unknown tag 0x${tag.toString(16)} at position ${position}`);
  }
};

export { isValid, parse };
