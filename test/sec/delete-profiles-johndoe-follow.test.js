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

t.test('DELETE /profiles/johndoe/follow', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, 'csrf'],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(60000)
  .run({
    method: 'DELETE',
    url: `${server.baseUrl}/profiles/johndoe/follow`,
    headers: {
      'Authorization': 'Token required_jwt_token'
    }
  })

  t.end()
})
