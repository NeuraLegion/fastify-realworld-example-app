'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('POST /api/users', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  t.teardown(() => runner.clear())

  await runner.createScan({
    tests: [
      TestType.CSRF,
      TestType.BRUTE_FORCE_LOGIN,
      TestType.MASS_ASSIGNMENT,
      TestType.SQLI,
      TestType.XSS
    ],
    attackParamLocations: [
      AttackParamLocation.BODY
    ]
  })
  .threshold(Severity.MEDIUM)
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