'use strict'
const t = require('tap');
const { SecRunner, TestType } = require('@sectester/runner');
const startServer = require('../setup-server');

const configuration = { hostname: 'app.brightsec.com' };

async function runSecurityTests() {
  const runner = new SecRunner(configuration);
  await runner.init();

  const scan = runner.createScan({
    tests: [
      TestType.JWT,
      TestType.BRUTE_FORCE_LOGIN,
      TestType.CSRF,
      TestType.EXCESSIVE_DATA_EXPOSURE,
      TestType.MASS_ASSIGNMENT,
      TestType.SQLI,
      TestType.XSS
    ]
  });

  const target = {
    method: 'PUT',
    url: 'http://localhost:3000/api/user',
    headers: {
      Authorization: 'Bearer <token>',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      user: {
        username: 'updateduser',
        email: 'updateduser@example.com',
        password: 'newpassword123'
      }
    })
  };

  await scan.run(target);
  await runner.clear();
}

runSecurityTests().catch(err => {
  console.error('Security tests failed:', err);
  process.exit(1);
});
