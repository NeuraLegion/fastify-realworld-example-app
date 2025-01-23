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
        TestType.JWT,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.SQLI,
        TestType.XSS,
        'mass_assignment',
        'insecure_output_handling'
      ],
      attackParamLocations: ['body']
    })
    .threshold('MEDIUM')
    .timeout(TEST_TIMEOUT)
    .run({
      method: 'PUT',
      url: 'http://localhost:3000/user',
      headers: {
        Authorization: 'Token jwt.token.here'
      },
      body: {
        user: {
          email: 'string',
          username: 'string',
          password: 'string',
          bio: 'string',
          image: 'string'
        }
      }
    })

    t.end()
  })

  t.end()
})
