// #B346 medium: settings.ts GET /notifications and GET /ai returned credential
// columns (bot tokens, webhook URLs, API keys) verbatim. Mask on read; PUT
// ignores a still-masked value (isMasked) so the edit form can round-trip
// unchanged fields without clobbering the real secret with the placeholder.
function maskSecret(value) {
  if (!value) return null;
  if (value.length <= 4) return '****';
  return '****' + value.slice(-4);
}

function isMasked(value) {
  return typeof value === 'string' && value.startsWith('****');
}

module.exports = { maskSecret, isMasked };
