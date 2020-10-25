import assert from 'assert';
import crc32 from 'buffer-crc32';

const validSilabsCrc32 = <const>0x2144df1c;

const imageSignature = <const>0xe350;

const eblTagHeader = <const>0x0;
const eblTagMetadata = <const>0xf608;
const eblTagProg = <const>0xfe01;
const eblTagMfgprog = <const>0x02fe;
const eblTagEraseprog = <const>0xfd03;
const eblTagEnd = <const>0xfc04;

const eblTagEncHeader = <const>0xfb05;
const eblTagEncInit = <const>0xfa06;
const eblTagEncEblData = <const>0xf907;
const eblTagEncMac = <const>0xf709;

const eblPadding = <const>0xff;

type EblHeader = {
  tag: typeof eblTagHeader;
  len: number;
  version: number;
  signature: typeof imageSignature;
  flashAddr: number;
  aatCrc: number;
  aatBuff: Buffer;
};

type EblEncHeader = {
  tag: typeof eblTagEncHeader;
  len: number;
  version: number;
  encType: number;
  signature: typeof imageSignature;
};

type EblProgElement = {
  tag: typeof eblTagProg | typeof eblTagMfgprog | typeof eblTagEraseprog;
  len: number;
  flashAddr: number;
  flashData: Buffer;
};

type EblMetadataElement = {
  tag: typeof eblTagMetadata;
  len: number;
  metadata: Buffer;
};

type EblEncInitElememt = {
  tag: typeof eblTagEncInit;
  len: number;
  msgLen: number;
  nonce: Buffer;
  associatedData: Buffer;
};

type EblEncEblDataElement = {
  tag: typeof eblTagEncEblData;
  len: number;
  data: Buffer;
};

type EblEncMacElement = {
  tag: typeof eblTagEncMac;
  len: number;
  eblMac: Buffer;
};

type EblEndElement = {
  tag: typeof eblTagEnd;
  len: number;
  eblCrc: number;
};

type EblElement = EblProgElement | EblMetadataElement | EblEncInitElememt | EblEncEblDataElement | EblEncMacElement | EblEndElement;

type EblData = {
  header: EblHeader | EblEncHeader;
  elements: EblElement[];
};

const isValid = (buffer: Buffer): boolean => {
  if (buffer.length < 10) {
    return false;
  }

  const tag = buffer.readUInt16BE();

  return tag === eblTagHeader || tag === eblTagEncHeader;
};

const parse = (buffer: Buffer): EblData => {
  const header = parseEblHeader(buffer);

  let position = 4 + header.len;
  const elements = [];
  while (position < buffer.length) {
    const element = parseEblSubElement(buffer, position);

    elements.push(element);

    position += 4 + element.len;

    if (element.tag === eblTagEnd) {
      break;
    }
  }

  const calculatedCrc32 = crc32.unsigned(buffer.slice(0, position));

  assert.strictEqual(calculatedCrc32, validSilabsCrc32, `Image CRC-32 is invalid`);

  while (position < buffer.length) {
    assert.strictEqual(buffer.readUInt8(position), eblPadding, `EBL padding contains invalid bytes`);

    position++;
  }

  return {
    header,
    elements,
  };
};

const parseEblHeader = (buffer: Buffer): EblHeader | EblEncHeader => {
  const tag = buffer.readUInt16BE();

  switch (tag) {
    case eblTagHeader: {
      assert.ok(buffer.length >= 16, `EBL header needs at least 16 bytes, but buffer only has ${buffer.length}`);

      const signature = buffer.readUInt16BE(6);

      assert.strictEqual(signature, imageSignature, `Not EBL data (failed signature check)`);

      const len = buffer.readUInt16BE(2);

      return {
        tag,
        len,
        version: buffer.readUInt16BE(4),
        signature,
        flashAddr: buffer.readUInt32BE(8),
        aatCrc: buffer.readUInt32BE(12),
        aatBuff: buffer.slice(16, len + 4),
      };
    }

    case eblTagEncHeader: {
      assert.ok(buffer.length >= 10, `EBL encrypted header needs at least 10 bytes, but buffer only has ${buffer.length}`);

      const len = buffer.readUInt16BE(2);

      assert.strictEqual(len, 6, `Incorrect EBL encrypted header length`);

      const signature = buffer.readUInt16BE(8);

      assert.strictEqual(signature, imageSignature, `Not EBL data (failed signature check)`);

      return {
        tag,
        len,
        version: buffer.readUInt16BE(4),
        encType: buffer.readUInt16BE(6),
        signature,
      };
    }

    default:
      throw new Error(`unknown header tag 0x${tag.toString(16)}`);
  }
};

const parseEblSubElement = (data: Buffer, position: number): EblElement => {
  const tag = data.readUInt16BE(position);
  const len = data.readUInt16BE(position + 2);

  switch (tag) {
    case eblTagProg:
    case eblTagMfgprog:
    case eblTagEraseprog:
      assert.ok(len >= 2 && len <= 65534, `Program subelement length should be between 2 and 65534, but was ${len}`);

      return {
        tag,
        len,
        flashAddr: data.readUInt32BE(position + 4),
        flashData: data.slice(position + 8, position + 4 + len),
      };

    case eblTagMetadata:
      assert.ok(len >= 1 && len <= 65534, `Metadata subelement length should be between 1 and 65534, but was ${len}`);

      return {
        tag,
        len,
        metadata: data.slice(position + 4, position + 4 + len),
      };

    case eblTagEncInit:
      return {
        tag,
        len,
        msgLen: data.readUInt32BE(position + 4),
        nonce: data.slice(position + 8, position + 20),
        associatedData: data.slice(position + 20, position + 4 + len),
      };

    case eblTagEncEblData:
      return {
        tag,
        len,
        data: data.slice(position + 4, position + 4 + len),
      };

    case eblTagEncMac:
      assert.ok(len === 16, `Encrypted Mac subelement length should be 16, but was ${len}`);

      return {
        tag,
        len,
        eblMac: data.slice(position + 4, position + 4 + len),
      };

    case eblTagEnd:
      assert.ok(len === 4, `End subelement length should be 4, but was ${len}`);

      return {
        tag,
        len,
        eblCrc: data.readUInt32BE(position + 4),
      };

    default:
      throw new Error(`Unknown tag 0x${tag.toString(16)} at position ${position}`);
  }
};

export { isValid, parse };
