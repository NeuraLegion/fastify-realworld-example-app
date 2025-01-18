'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('DELETE /profiles/johndoe/follow', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  // Initialize SecTester runner
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  // Clear SecTester runner after each test
  t.teardown(() => runner.clear())

  // Run security tests
  await runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'csrf', 'http_method_fuzzing'],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'DELETE',
    url: `${server.baseUrl}/profiles/johndoe/follow`,
    headers: { 'Authorization': 'Bearer <token>' }
  })

  t.end()
})