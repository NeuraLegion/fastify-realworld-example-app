'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

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


t.test('POST /api/users', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.CSRF, TestType.BRUTE_FORCE_LOGIN, TestType.MASS_ASSIGNMENT, TestType.SQLI, TestType.XSS],
    attackParamLocations: ['body', 'header']
  })
  .threshold('medium')
  .timeout(60000)
  .run({
    method: 'POST',
    url: 'http://localhost:3000/api/users',
    headers: { 'Content-Type': 'application/json' },
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
