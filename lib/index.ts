import * as eblParser from './eblParser';
import * as gblParser from './gblParser';

const getFormat = (buffer: Buffer): 'ebl' | 'gbl' | undefined => {
  if (gblParser.isValid(buffer)) {
    return 'gbl';
  } else if (eblParser.isValid(buffer)) {
    return 'ebl';
  }

  return undefined;
};

export { getFormat, gblParser, eblParser };
