'use strict'
const t = require('tap');
const { SecRunner, SecScan } = require('@sectester/runner');
const { TestType } = require('@sectester/scan');
const startServer = require('../setup-server');

const configuration = { hostname: 'app.brightsec.com' };

let runner;
let scan;

async function setupRunner() {
  runner = new SecRunner(configuration);
  await runner.init();
  scan = runner.createScan({ tests: [TestType.BRUTE_FORCE_LOGIN, TestType.CSRF, TestType.SQLI, TestType.XSS] });
}

async function teardownRunner() {
  await runner.clear();
}

async function runSecurityTests() {
  const server = await startServer();
  t.teardown(() => server.close());

  await scan.run({
    method: 'POST',
    url: 'http://localhost:3000/api/users/login',
    headers: { 'Content-Type': 'application/json' },
    body: { user: { email: 'user@example.com', password: 'password123' } }
  });
}

setupRunner()
  .then(runSecurityTests)
  .then(teardownRunner)
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
