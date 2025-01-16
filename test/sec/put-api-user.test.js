'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner


t.test('setup', async t => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()
  t.end()
})

t.teardown(async () => {
  await runner.clear()
})


t.test('PUT /api/user', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner
    .createScan({
      tests: [TestType.JWT, TestType.CSRF, TestType.BRUTE_FORCE_LOGIN, 'mass_assignment', TestType.SQLI, TestType.XSS],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'PUT',
      url: 'http://localhost:3000/api/user',
      headers: {
        'Authorization': 'Bearer <token>',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: {
          email: 'updated@example.com',
          password: 'newpassword123'
        }
      })
    })

  t.end()
})
