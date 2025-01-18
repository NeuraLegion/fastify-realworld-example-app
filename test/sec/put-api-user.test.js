'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('PUT /api/user', async t => {
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

  t.test('Security tests for PUT /api/user', async t => {
    await runner
      .createScan({
        tests: [
          TestType.JWT,
          TestType.CSRF,
          TestType.BRUTE_FORCE_LOGIN,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.MASS_ASSIGNMENT,
          TestType.SQLI,
          TestType.XSS
        ],
        attackParamLocations: [
          AttackParamLocation.BODY,
          AttackParamLocation.HEADER
        ]
      })
      .threshold(Severity.MEDIUM)
      .timeout(testTimeout)
      .run({
        method: 'PUT',
        url: `${baseUrl}/api/user`,
        headers: {
          'Authorization': 'Bearer <token>',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          user: {
            email: 'updateduser@example.com',
            password: 'newpassword123'
          }
        })
      })

    t.end()
  })

  t.end()
})
