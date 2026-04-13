import axios from 'axios';
import jwt from 'jsonwebtoken';

const token = jwt.sign({ id: 1, companyId: 1, role: 'Admin' }, process.env.JWT_SECRET || "pharmaflow-dev-secret-key-2026", { expiresIn: '8h' });

async function test() {
  try {
    const res = await axios.get('http://localhost:3000/api/workflows', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'x-company-id': '1'
      }
    });
    console.log(res.data);
  } catch (e: any) {
    console.error(e.response ? e.response.data : e.message);
  }
}
test();
