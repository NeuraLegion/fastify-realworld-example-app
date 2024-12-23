'use strict'
const t = require('tap');
const { SecRunner, TestType } = require('@sectester/runner');
const startServer = require('../setup-server');

const BRIGHT_HOSTNAME = process.env.BRIGHT_HOSTNAME || 'app.brightsec.com';
const BRIGHT_TOKEN = process.env.BRIGHT_TOKEN;

if (!BRIGHT_TOKEN) {
  throw new Error('BRIGHT_TOKEN environment variable is not set');
}

const runner = new SecRunner({ hostname: BRIGHT_HOSTNAME, token: BRIGHT_TOKEN });

async function runSecurityTests() {
  await runner.init();

  t.test('POST /api/users - SQL Injection', async t => {
    const server = await startServer();
    t.teardown(() => server.close());

    const scan = runner.createScan({ tests: [TestType.SQLI] });

    await scan.run({
      method: 'POST',
      url: 'http://localhost:3000/api/users',
      body: {
        user: {
          username: "newuser",
          email: "newuser@example.com",
          password: "password123"
        }
      }
    });

    t.pass('SQL Injection test completed');
    t.end();
  });

  await runner.clear();
}

runSecurityTests().catch(err => {
  console.error(err);
  process.exit(1);
});
