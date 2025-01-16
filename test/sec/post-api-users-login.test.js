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

t.test('POST /api/users/login security tests', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.BRUTE_FORCE, TestType.CSRF, TestType.SQLI, TestType.XSS],
    attackParamLocations: [AttackParamLocation.BODY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000) // 15 minutes
  .run({
    method: 'POST',
    url: 'http://localhost:3000/api/users/login',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: { email: 'example@example.com', password: 'password123' } })
  })

  t.end()
})
