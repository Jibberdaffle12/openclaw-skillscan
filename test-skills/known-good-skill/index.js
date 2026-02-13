// A simple, clean skill that reads files and summarizes them.
// No outbound connections, no dangerous patterns.

const fs = require('fs');
const path = require('path');

function summarize(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const wordCount = content.split(/\s+/).length;
  
  return {
    filename: path.basename(filePath),
    lines: lines.length,
    words: wordCount,
    preview: lines.slice(0, 3).join('\n')
  };
}

module.exports = { summarize };
