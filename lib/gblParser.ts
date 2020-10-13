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

type GblHeader = {
  tag: typeof gblTagHeader;
  len: number;
  version: number;
  type: number;
};

type GblApplicationElement = {
  tag: typeof gblTagApplication;
  len: number;
  type: number;
  version: number;
  capabilities: number;
  productId: Buffer;
};

type GblBootloaderElement = {
  tag: typeof gblTagBootloader;
  len: number;
  bootloaderVersion: number;
  address: number;
  data: Buffer;
};

type GblSeUpgradeElement = {
  tag: typeof gblTagSeUpgrade;
  len: number;
  blobSize: number;
  version: number;
  data: Buffer;
};

type GblMetadataElement = {
  tag: typeof gblTagMetadata;
  len: number;
  metaData: Buffer;
};

type GblProgElement = {
  tag: typeof gblTagProg | typeof gblTagEraseProg;
  len: number;
  flashStartAddress: number;
  data: Buffer;
};

type GblEndElement = {
  tag: typeof gblTagEnd;
  len: number;
  eblCrc: number;
};

type GblElement = GblApplicationElement | GblBootloaderElement | GblSeUpgradeElement | GblMetadataElement | GblProgElement | GblEndElement;

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

  assert.strictEqual(position, buffer.length, `Image contains trailing data`);

  const calculatedCrc32 = crc32.unsigned(buffer);

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
        type: data.readUInt32BE(position + 8),
        version: data.readUInt32BE(position + 12),
        capabilities: data.readUInt32BE(position + 16),
        productId: data.slice(position + 20),
      };

    case gblTagBootloader:
      return {
        tag,
        len,
        bootloaderVersion: data.readUInt32BE(position + 8),
        address: data.readUInt32BE(position + 12),
        data: data.slice(position + 16),
      };

    case gblTagSeUpgrade:
      return {
        tag,
        len,
        blobSize: data.readUInt32BE(position + 8),
        version: data.readUInt32BE(position + 12),
        data: data.slice(position + 16),
      };

    case gblTagMetadata:
      return {
        tag,
        len,
        metaData: data.slice(position + 8),
      };

    case gblTagProg:
    case gblTagEraseProg:
      return {
        tag,
        len,
        flashStartAddress: data.readUInt32BE(position + 8),
        data: data.slice(position + 12),
      };

    case gblTagEnd:
      return {
        tag,
        len,
        eblCrc: data.readUInt32BE(position + 8),
      };

    default:
      throw new Error(`unknown tag 0x${tag.toString(16)} at position ${position}`);
  }
};

export { isValid, parse };
