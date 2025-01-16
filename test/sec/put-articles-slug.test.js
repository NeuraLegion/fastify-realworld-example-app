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



// Test cases will be added here

t.test('PUT /api/articles/{slug}', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.JWT, TestType.CSRF, TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
    attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER, AttackParamLocation.PATH]
  })
  .threshold(Severity.MEDIUM)
  .timeout(60000)
  .run({
    method: 'PUT',
    url: `${server.baseUrl}/api/articles/test-article`,
    headers: {
      'Authorization': 'Token jwt.token.here',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      article: {
        title: 'string',
        description: 'string',
        body: 'string'
      }
    })
  })

  t.end()
})
