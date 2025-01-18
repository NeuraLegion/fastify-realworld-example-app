'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for POST /api/users/login', async t => {
  let server

  t.beforeEach(async () => {
    server = await startServer()
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.teardown(async () => {
    await runner.clear()
    await server.close()
  })

  t.test('Run security tests', async t => {
    await runner.createScan({
      tests: [
        TestType.BRUTE_FORCE_LOGIN,
        TestType.CSRF,
        TestType.SQLI,
        TestType.XSS,
        'insecure_output_handling'
      ],
      attackParamLocations: ['body']
    })
    .threshold('medium')
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

  t.end()
})
