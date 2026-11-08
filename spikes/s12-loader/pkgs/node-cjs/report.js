const fs = require('fs'), path = require('path'), crypto = require('crypto');
module.exports = (first) => {
  first.hash = first.has ? crypto.createHash('sha256').update(process.env.SPIKE_SECRET).digest('hex') : '';
  first.fds = fs.readdirSync('/proc/self/fd').map((f) => { try { return f + '=' + fs.readlinkSync('/proc/self/fd/' + f); } catch (e) { return f; } });
  first.nazarLeft = Object.keys(process.env).filter((k) => k.startsWith('NAZAR_'));
  first.nodeOptions = process.env.NODE_OPTIONS || '';
  fs.writeFileSync(path.join(process.env.SPIKE_REPORT_DIR, 'target-' + process.pid + '.json'), JSON.stringify(first));
  if (process.env.SPIKE_STAY) setInterval(() => {}, 1000);
};
