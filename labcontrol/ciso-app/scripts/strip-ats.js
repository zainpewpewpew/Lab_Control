// electron-builder afterPack hook.
// Deletes the Electron-template NSAppTransportSecurity block from Info.plist so the
// packaged app does not ship with NSAllowsArbitraryLoads=true + TLS 1.0 exceptions.
// Chromium ignores ATS at runtime, so the block was never load-bearing; stripping it
// removes a false positive during Gatekeeper / notarization / security review.
const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

exports.default = async function (context) {
  if (context.electronPlatformName !== 'darwin') return;
  const plist = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`, 'Contents', 'Info.plist');
  if (!fs.existsSync(plist)) return;
  try {
    execFileSync('/usr/libexec/PlistBuddy', ['-c', 'Delete :NSAppTransportSecurity', plist], { stdio: 'ignore' });
  } catch (_) {
    // Key was already absent.
  }
};
