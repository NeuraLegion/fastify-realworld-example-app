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


t.test('POST /profiles/johndoe/follow', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.JWT, TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, 'HTTP_METHOD_FUZZING'],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000) // 15 minutes
  .run({
    method: 'POST',
    url: `${server.baseUrl}/profiles/johndoe/follow`,
    headers: {
      'Authorization': 'Token required_jwt_token'
    },
    body: {}
  })

  t.end()
})
