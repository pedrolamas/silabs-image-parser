import fs from 'fs';
import path from 'path';
import zhc from 'zigbee-herdsman-converters/ota/common';
import { getFormat, eblParser, gblParser } from '..';

type OtaImages = [
  string,
  {
    format: string;
  }
];

const otaImages: OtaImages[] = [
  ['10005777-4.1-TRADFRI-control-outlet-2.0.024.ota.ota.signed', { format: 'gbl' }],
  ['10035514-2.1-TRADFRI-bulb-ws-2.3.050.ota.ota.signed', { format: 'ebl' }],
];

describe('Parse images', () => {
  test.each(otaImages)(`Can parse "%s"`, (filename, meta) => {
    const data = fs.readFileSync(path.join(__dirname, 'otaImageFiles', filename));

    // fix for IKEA OTA images
    const start = data.readUInt32LE(0) === 0x5349474e ? 12 + data.readUInt16LE(12) : 0;

    const image = zhc.parseImage(data.slice(start));

    image.elements.forEach((element: { data: Buffer }) => {
      const format = getFormat(element.data);

      expect(format).toBe(meta.format);

      switch (format) {
        case 'gbl':
          expect(gblParser.parse(element.data)).not.toBeUndefined();

          break;

        case 'ebl':
          expect(eblParser.parse(element.data)).not.toBeUndefined();

          break;
      }
    });
  });
});
