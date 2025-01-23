'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for POST /users', async t => {
  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.teardown(async () => {
    await runner.clear()
  })

  t.test('initialize server', async t => {
    const server = await startServer()
    t.teardown(() => server.close())

    await runner.createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        'email_injection',
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.MASS_ASSIGNMENT,
        'password_reset_poisoning',
        TestType.SQLI,
        TestType.XSS
      ],
      attackParamLocations: ['body']
    })
    .threshold('medium')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'POST',
      url: '/users',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: {
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'password123'
        }
      })
    })

    t.end()
  })

  t.end()
})
