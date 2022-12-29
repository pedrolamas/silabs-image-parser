declare module 'zigbee-herdsman-converters/lib/ota/common' {
  export type OTAImage = {
    elements: OTAImageElement[];
  };

  export type OTAImageElement = {
    data: Buffer;
  };

  export const parseImage: (buffer: Buffer) => OTAImage;
}
