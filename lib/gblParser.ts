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

const gblTagEncHeader = 0xfb0505fb;
const gblTagEncInit = <const>0xfa0606fa;
const gblTagEncEblData = <const>0xf90707f9;
const gblTagEncMac = 0xf70909f7;
const gblTagSignatureEcdsaP256 = 0xf70a0af7;
const gblTagCertificateEcdsaP256 = 0xf30b0bf3;

const gblPadding = <const>0x0;

type GblTagBase<T> = {
  tag: T;
  len: number;
};

type GblHeader = GblTagBase<typeof gblTagHeader> & {
  version: number;
  type: number;
};

type GblApplicationElement = GblTagBase<typeof gblTagApplication> & {
  type: number;
  version: number;
  capabilities: number;
  productId: Buffer;
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
  nouce: number;
};

type GblEncryptionDataElement = GblTagBase<typeof gblTagEncEblData> & {
  encryptedEblData: Buffer;
};

type GblTagEncryptionAesCcmSignatureElement = GblTagBase<typeof gblTagEncMac> & {
  eblMac: number;
};

type GblCertificateEcdsaP256Element = GblTagBase<typeof gblTagCertificateEcdsaP256> & {
  applicationCertificate: Buffer;
};

type GblSignatureEcdsaP256Element = GblTagBase<typeof gblTagSignatureEcdsaP256> & {
  r: number;
  s: number;
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

  while (position < buffer.length) {
    assert.strictEqual(buffer.readUInt8(position), gblPadding, `GBL padding contains invalid bytes`);

    position++;
  }

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
        type: data.readUInt32BE(position + 8),
        version: data.readUInt32BE(position + 12),
        capabilities: data.readUInt32BE(position + 16),
        productId: data.slice(position + 20, position + 8 + len),
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
      return {
        tag,
        len,
        eblCrc: data.readUInt32BE(position + 8),
      };

    case gblTagEncHeader:
      return {
        tag,
        len,
        version: data.readUInt32BE(position + 8),
        magicWord: data.readUInt32BE(position + 12),
        encryptionType: data.readUInt32BE(position + 16),
      };

    case gblTagEncInit:
      return {
        tag,
        len,
        msgLen: data.readUInt32BE(position + 8),
        nouce: data.readUInt8(position + 12),
      };

    case gblTagEncEblData:
      return {
        tag,
        len,
        encryptedEblData: data.slice(position + 8, position + 8 + len),
      };

    case gblTagEncMac:
      return {
        tag,
        len,
        eblMac: data.readInt8(position + 8),
      };

    case gblTagCertificateEcdsaP256:
      return {
        tag,
        len,
        applicationCertificate: data.slice(position + 8, position + 8 + len),
      };

    case gblTagSignatureEcdsaP256:
      return {
        tag,
        len,
        r: data.readUInt32BE(position + 8),
        s: data.readUInt32BE(position + 9),
      };

    default:
      throw new Error(`Unknown tag 0x${tag.toString(16)} at position ${position}`);
  }
};

export { isValid, parse };
