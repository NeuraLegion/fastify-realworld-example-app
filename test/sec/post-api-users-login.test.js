'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

// Set timeout for tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('POST /api/users/login', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  // Initialize SecTester runner
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  // Clear SecTester runner after each test
  t.teardown(() => runner.clear())

  // Run security tests
  await runner.createScan({
    tests: [
      TestType.BRUTE_FORCE_LOGIN,
      TestType.CSRF,
      TestType.EXCESSIVE_DATA_EXPOSURE,
      'INSECURE_OUTPUT_HANDLING',
      TestType.SQLI,
      TestType.XSS
    ],
    attackParamLocations: ['BODY', 'HEADER']
  })
  .threshold('MEDIUM')
  .timeout(15 * 60 * 1000)
  .run({
    method: 'POST',
    url: 'http://localhost:3000/api/users/login',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      user: {
        email: 'user@example.com',
        password: 'password123'
      }
    })
  })

  t.end()
})