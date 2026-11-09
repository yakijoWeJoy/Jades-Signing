export class JadesFormatError extends Error {
  constructor(message, code = 'MALFORMED_INPUT') {
    super(message);
    this.name = 'JadesFormatError';
    this.code = code;
  }
}
