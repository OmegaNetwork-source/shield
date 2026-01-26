// STRIX Scanner Tests - Main Export
// Comprehensive security testing modules

export * from './injection';
export * from './directory-enum';
export * from './owasp';
export * from './ssl';
export * from './fingerprint';

import injection from './injection';
import directoryEnum from './directory-enum';
import owasp from './owasp';
import ssl from './ssl';
import fingerprint from './fingerprint';

export const tests = {
    injection,
    directoryEnum,
    owasp,
    ssl,
    fingerprint
};

export default tests;
