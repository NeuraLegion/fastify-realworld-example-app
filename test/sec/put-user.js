'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for PUT /user', async t => {
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
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.SQLI,
        TestType.XSS,
        'email_injection',
        'brute_force_login',
        'password_reset_poisoning'
      ],
      attackParamLocations: ['body', 'header']
    })
    .threshold('medium')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'PUT',
      url: '/user',
      headers: {
        Authorization: 'Bearer <token>'
      },
      payload: {
        user: {
          username: 'updateduser',
          email: 'updateduser@example.com',
          password: 'newpassword123'
        }
      }
    })

    t.end()
  })

  t.end()
})
