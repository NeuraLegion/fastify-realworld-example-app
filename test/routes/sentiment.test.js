'use strict'
const t = require('tap');
const { Configuration, SecRunner } = require('@sectester/runner');
const { TestType } = require('@sectester/scan');
const startServer = require('../setup-server');

const configuration = new Configuration({ hostname: 'app.brightsec.com' });

let runner;

async function setupRunner() {
  runner = new SecRunner(configuration);
  await runner.init();
}

async function teardownRunner() {
  if (runner) {
    await runner.clear();
  }
}

async function runScan() {
  const scan = runner.createScan({ tests: [TestType.XSS] });
  await scan.run({
    method: 'POST',
    url: 'http://localhost:3000/sentiment/score',
    headers: { Authorization: 'Bearer <token>' },
    body: { content: 'string' }
  });
}

setupRunner();

// Test for the /sentiment/score endpoint

t.test('POST /sentiment/score should not have XSS', async t => {
  const server = await startServer();
  t.teardown(() => server.close());
  t.teardown(teardownRunner);

  try {
    await runScan();
    t.pass('No XSS vulnerability found');
  } catch (error) {
    t.fail(`XSS vulnerability found: ${error.message}`);
  }

  t.end();
});
