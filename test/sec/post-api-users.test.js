'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for POST /api/users', async t => {
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

  t.test('POST /api/users', async t => {
    await runner.createScan({
      tests: [
        TestType.CSRF,
        TestType.BRUTE_FORCE_LOGIN,
        TestType.MASS_ASSIGNMENT,
        TestType.SQLI,
        TestType.XSS,
        'EMAIL_INJECTION'
      ],
      attackParamLocations: ['BODY']
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000)
    .run({
      method: 'POST',
      url: 'http://localhost:3000/api/users',
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
