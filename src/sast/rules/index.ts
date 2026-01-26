// STRIX SAST Rules Index
// Export all detection rules

export * from './secrets';
export * from './vulnerabilities';

import secretPatterns from './secrets';
import vulnerabilityRules from './vulnerabilities';

export const rules = {
    secrets: secretPatterns,
    vulnerabilities: vulnerabilityRules,
};

export default rules;
