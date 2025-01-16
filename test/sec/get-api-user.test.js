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


// Security test for GET /api/user

t.test('GET /api/user', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'EXCESSIVE_DATA_EXPOSURE', TestType.CSRF],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000) // 15 minutes
  .run({
    method: 'GET',
    url: 'http://localhost:3000/api/user',
    headers: [{ name: 'Authorization', value: 'Bearer <token>' }]
  })

  t.end()
})
