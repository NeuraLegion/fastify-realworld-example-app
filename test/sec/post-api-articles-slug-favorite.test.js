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

t.test('POST /api/articles/{slug}/favorite', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.JWT, TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, 'HTTP_METHOD_FUZZING', TestType.XSS],
    attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
  })
  .threshold(Severity.MEDIUM)
  .timeout(60000)
  .run({
    method: 'POST',
    url: '/api/articles/{slug}/favorite',
    headers: { 'Authorization': 'Token jwt.token.here' },
    body: ''
  })

  t.end()
})
