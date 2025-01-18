'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for POST /articles', async t => {
  let server

  t.beforeEach(async () => {
    server = await startServer()
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.teardown(async () => {
    await runner.clear()
    await server.close()
  })

  await runner.createScan({
    tests: [TestType.JWT, 'csrf', TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
    attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'POST',
    url: `${server.baseUrl}/articles`,
    headers: {
      'Authorization': 'Token jwt.token.here',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      article: {
        title: 'string',
        description: 'string',
        body: 'string',
        tagList: ['string']
      }
    })
  })

  t.end()
})
