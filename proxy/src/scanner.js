const { request } = require('undici');
const { FormData } = require('undici');
const config = require('./config');

async function scanTarball(tarballBuffer, packageName, version) {
  try {
    const formData = new FormData();
    // Wrap buffer in a Blob-like object for undici FormData
    formData.append('tarball', new Blob([tarballBuffer]), 'package.tgz');

    const response = await request(`${config.SCAN_API_URL}/scan/tarball`, {
      method: 'POST',
      body: formData,
      headersTimeout: config.SCAN_TIMEOUT,
      bodyTimeout: config.SCAN_TIMEOUT,
    });

    if (response.statusCode !== 200) {
      return { verdict: 'error', error: `Scanner returned HTTP ${response.statusCode}` };
    }

    const data = await response.body.json();
    return data;
  } catch (err) {
    return { verdict: 'error', error: err.message };
  }
}

module.exports = {
  scanTarball
};
