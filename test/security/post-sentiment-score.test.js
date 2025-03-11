const t = require('tap');
const startServer = require('../setup-server');
const { SecRunner } = require('@sectester/runner');
const { Severity, AttackParamLocation, HttpMethod } = require('@sectester/scan');

let app;
let baseUrl;
let runner;

// Set a timeout for the tests
// Adjust the timeout as needed
// Here, it's set to 40 minutes
t.setTimeout(40 * 60 * 1000); // 40 minutes

// Before all tests, start the application and initialize SecTester
t.before(async () => {
  // Start the Fastify application
  app = await startServer();

  // Listen on a random port
  baseUrl = await app.listen({ port: 0 });

  // Initialize the SecRunner with environment variables
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
    projectId: process.env.BRIGHT_PROJECT_ID
  });

  // Initialize the runner
  await runner.init();
});

// After all tests, clear the runner and close the application
t.teardown(async () => {
  // Clear the runner
  await runner.clear();

  // Close the Fastify application
  await app.close();
});

// Test cases
t.test('POST /sentiment/score', async t => {
  t.setTimeout(40 * 60 * 1000); // 40 minutes

  const promise = runner
    .createScan({
      tests: ['excessive_data_exposure', 'mass_assignment', 'nosql', 'xss'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/sentiment/score`,
      body: { content: 'Sample text to analyze sentiment.' }
    });

  await t.resolves(promise);
});
