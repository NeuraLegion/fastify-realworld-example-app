'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('POST /users/login security tests', async t => {
  let server
  t.before(async () => {
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

  t.test('brute_force_login, csrf, sqli, xss, insecure_output_handling', async t => {
    await runner.createScan({
      tests: [
        TestType.BruteForceLogin,
        TestType.Csrf,
        TestType.Sqli,
        TestType.Xss,
        'insecure_output_handling'
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: '/users/login',
      body: {
        user: {
          email: 'user@example.com',
          password: 'password123'
        }
      },
      headers: {
        'Content-Type': 'application/json'
      }
    })

    t.end()
  })

  t.end()
})