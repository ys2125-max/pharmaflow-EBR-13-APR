import { db } from './server/db.ts';

try {
  const rows = db.prepare("SELECT * FROM workflow_steps").all();
  console.log(rows);
} catch (e) {
  console.error(e);
}
