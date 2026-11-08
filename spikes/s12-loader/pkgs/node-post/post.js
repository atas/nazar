// A dependency's install script: a node process npm starts while installing the target.
require('fs').writeFileSync(require('path').join(process.env.SPIKE_REPORT_DIR, 'postinstall-' + process.pid + '.json'), JSON.stringify({ pid: process.pid, has: 'SPIKE_SECRET' in process.env }));
