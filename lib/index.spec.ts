import fs from 'fs';
import path from 'path';
import zhc from 'zigbee-herdsman-converters/lib/ota/common';
import { expect } from 'chai';

import { getFormat, eblParser, gblParser } from '.';

type OtaImage = [
  string,
  {
    format: (index: number) => string | undefined;
  }
];

const otaImages: OtaImage[] = [
  ['10005777-4.1-TRADFRI-control-outlet-2.0.024.ota.ota.signed', { format: () => 'gbl' }],
  ['10035514-2.1-TRADFRI-bulb-ws-2.3.050.ota.ota.signed', { format: () => 'ebl' }],
  ['100B-0112-01001500-ConfLightBLE-Lamps-EFR32MG13.zigbee', { format: (index: number) => (index == 0 ? undefined : 'gbl') }],
  ['ED_Smoke_Sensor_SSIG_4.0.2.zigbee', { format: () => undefined }],
];

describe('Parse images', () => {
  otaImages.forEach((otaImage) => {
    const [filename, meta] = otaImage;

    it(`Can parse "${filename}"`, () => {
      const data = fs.readFileSync(path.join(__dirname, '__otaImageFiles__', filename));

      // fix for IKEA OTA images
      const start = data.readUInt32LE(0) === 0x5349474e ? 12 + data.readUInt16LE(12) : 0;

      const image = zhc.parseImage(data.slice(start));

      image.elements.forEach((element: { data: Buffer }, index) => {
        const format = getFormat(element.data);

        expect(format).to.equal(meta.format(index));

        switch (format) {
          case 'gbl':
            expect(gblParser.parse(element.data)).to.not.be.undefined;

            break;

          case 'ebl':
            expect(eblParser.parse(element.data)).to.not.be.undefined;

            break;
        }
      });
    });
  });
});
