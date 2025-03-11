const t = require('tap');
const startServer = require('../setup-server');
const { SecRunner } = require('@sectester/runner');
const { Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let app;
let baseUrl;
let runner;

// Set the timeout for the test to 40 minutes
const TEST_TIMEOUT = 40 * 60 * 1000;

// Set the relevant security tests
const tests = ['excessive_data_exposure', 'mass_assignment', 'xss', 'csrf'];

// Set the attack parameter locations
const attackParamLocations = [AttackParamLocation.BODY, AttackParamLocation.HEADER];

// Set the threshold
const threshold = Severity.CRITICAL;

// Set the HTTP method
const method = HttpMethod.POST;

// Set the endpoint URL
const endpointUrl = '/api/sentiment/score';

// Set the post data
const postData = { content: "You have done an excellent job. Well done!" };

// Set the headers
const headers = { 'Content-Type': 'application/json' };

// Set the skipStaticParams for date_manipulation test
const skipStaticParams = false;

// Setup and teardown

t.before(async () => {
  app = await startServer();
  baseUrl = await app.listen({ port: 0 });

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
    projectId: process.env.BRIGHT_PROJECT_ID
  });

  await runner.init();
});

t.teardown(async () => {
  await runner.clear();
  await app.close();
});

// Test case

t.test('POST /api/sentiment/score', async t => {
  t.setTimeout(TEST_TIMEOUT);

  const promise = runner
    .createScan({
      tests,
      attackParamLocations,
      skipStaticParams
    })
    .threshold(threshold)
    .timeout(TEST_TIMEOUT)
    .run({
      method,
      url: `${baseUrl}${endpointUrl}`,
      headers,
      body: postData
    });

  await t.resolves(promise);
});
