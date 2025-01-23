'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Set timeout for the tests
const TEST_TIMEOUT = 15 * 60 * 1000 // 15 minutes

t.test('Security tests for POST /users/login', async t => {
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
        TestType.BRUTE_FORCE_LOGIN,
        TestType.CSRF,
        TestType.SQLI,
        TestType.XSS,
        'insecure_output_handling'
      ],
      attackParamLocations: ['body']
    }).run({
      method: 'POST',
      url: '/users/login',
      headers: {
        'Content-Type': 'application/json'
      },
      body: {
        user: {
          email: 'user@example.com',
          password: 'password123'
        }
      }
    })

    t.end()
  })

  t.end()
})
