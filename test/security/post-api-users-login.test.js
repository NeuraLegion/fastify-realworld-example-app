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

// Test cases will be added here
t.test('POST /api/users/login', async t => {
  t.setTimeout(40 * 60 * 1000); // 40 minutes

  const promise = runner
    .createScan({
      tests: ['csrf', 'excessive_data_exposure', 'mass_assignment', 'jwt', 'sqli'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(40 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/users/login`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: {
          email: 'example@example.com',
          password: 'password123'
        }
      })
    });

  await t.resolves(promise);
});
