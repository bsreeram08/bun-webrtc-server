import { createInvite, openDatabase } from '../packages/signaling/accounts';

// Run on the trusted host. Prints a single-use, 7-day account invitation; only its hash is stored.
const db = openDatabase(process.env.DATA_DIR || 'data');
const { code, expiresAt } = createInvite(db, null);
db.close();
console.log(`Invite code: ${code}`);
console.log(`Expires: ${new Date(expiresAt).toISOString()}`);
if (process.env.PUBLIC_ORIGIN) console.log(`Link: ${process.env.PUBLIC_ORIGIN}/#invite=${code}`);
