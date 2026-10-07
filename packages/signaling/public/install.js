'use strict';
// Only public app files are cached. Invitations and API responses stay out of
// the offline cache; chat history lives in the device's IndexedDB instead.
if (window.isSecureContext && 'serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}
