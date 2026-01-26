// STRIX SAST Reports Module
// Export all SAST report generators

export * from './sast-pdf-report';

import { generateSASTReport, downloadSASTReport } from './sast-pdf-report';

export default {
    generateSASTReport,
    downloadSASTReport
};
