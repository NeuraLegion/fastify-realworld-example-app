'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner } = require('@sectester/runner');
const { TestType } = require('@sectester/scan');

const configuration = { hostname: 'app.brightsec.com' };

let runner;

async function setupRunner() {
  runner = new SecRunner(configuration);
  await runner.init();
}

async function teardownRunner() {
  await runner.clear();
}

async function runScan(testType, target) {
  const scan = runner.createScan({ tests: [testType] });
  await scan.run(target);
}

setupRunner();

const target = {
  method: 'GET',
  url: 'http://localhost:3000/api/user',
  headers: { Authorization: 'Bearer <token>' }
};

// Test for broken access control
runScan('broken_access_control', target);

// Test for JWT issues
runScan(TestType.JWT, target);

// Test for excessive data exposure
runScan('excessive_data_exposure', target);

teardownRunner();

// Example test from the repository

 t.test('get current user without login', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/api/user'
  })
  t.equal(response.statusCode, 401, 'returns a status code of 401 Unauthorized')
  t.end()
})