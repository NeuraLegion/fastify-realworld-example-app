'use strict'
const t = require('tap');
const { SecRunner } = require('@sectester/runner');
const { TestType } = require('@sectester/scan');
const startServer = require('../setup-server');

const configuration = { hostname: 'app.brightsec.com' };

let runner;

async function setupRunner() {
  runner = new SecRunner(configuration);
  await runner.init();
}

async function teardownRunner() {
  await runner.clear();
}

async function runSecurityTests() {
  const scan = runner.createScan({
    tests: [
      TestType.JWT,
      'broken_access_control',
      'excessive_data_exposure',
      TestType.HTTP_METHOD_FUZZING,
      TestType.ID_ENUMERATION
    ]
  });

  await scan.run({
    method: 'GET',
    url: 'http://localhost:3000/articles/feed',
    headers: { Authorization: 'Token jwt.token.here' },
    query: { limit: '20', offset: '0' }
  });
}

setupRunner();

teardownRunner();

// Test case for /articles/feed endpoint

 t.test('GET /articles/feed security tests', async t => {
  const server = await startServer();
  t.teardown(() => server.close());

  await runSecurityTests();

  t.end();
});
