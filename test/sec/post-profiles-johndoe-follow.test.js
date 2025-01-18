'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('POST /profiles/johndoe/follow', async t => {
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
      TestType.BROKEN_ACCESS_CONTROL,
      TestType.CSRF,
      TestType.JWT,
      'BRUTE_FORCE_LOGIN',
      'BUSINESS_CONSTRAINT_BYPASS'
    ],
    attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'POST',
    url: `${server.baseUrl}/profiles/johndoe/follow`,
    headers: {
      'Authorization': 'Bearer <token>'
    },
    body: {}
  })

  t.end()
})