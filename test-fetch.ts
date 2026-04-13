import { db } from './server/db.ts';

try {
  const rows = db.prepare("SELECT * FROM workflows WHERE company_id = 1").all();
  console.log(rows);
} catch (e) {
  console.error(e);
}
