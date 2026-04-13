import axios from 'axios';

async function test() {
  try {
    const res = await axios.post('http://localhost:3000/api/errors/analyze', {
      error: 'Test error',
      stack: 'Test stack',
      context: {},
      source: 'test'
    });
    console.log(res.data);
  } catch (e: any) {
    console.error(e.response ? e.response.data : e.message);
  }
}
test();
