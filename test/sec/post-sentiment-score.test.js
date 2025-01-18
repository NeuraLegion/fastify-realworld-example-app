'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('SecTester integration for POST /sentiment/score', async t => {
  let server
  let baseUrl

  t.before(async () => {
    server = await startServer()
    const address = server.server.address()
    baseUrl = `http://localhost:${address.port}`
  })

  t.teardown(() => server.close())

  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.afterEach(() => runner.clear())

  // Placeholder for actual test cases
  t.test('Security tests for POST /sentiment/score', async t => {
    await runner.createScan({
      tests: [
        TestType.CSRF,
        TestType.XSS,
        TestType.SQLI,
        'excessive_data_exposure',
        'business_constraint_bypass'
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(testTimeout)
    .run({
      method: 'POST',
      url: `${baseUrl}/sentiment/score`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        content: 'string'
      })
    })

    t.end()
  })

  t.end()
})
