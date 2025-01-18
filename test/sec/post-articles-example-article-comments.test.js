'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('POST /articles/example-article/comments', async t => {
  let server
  let baseUrl

  t.before(async () => {
    server = await startServer()
    const address = server.server.address()
    baseUrl = `http://localhost:${address.port}`
  })

  t.teardown(() => server.close())

  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.afterEach(() => runner.clear())

  t.test('security tests', async t => {
    await runner
      .createScan({
        tests: [
          TestType.CSRF,
          TestType.JWT,
          TestType.XSS,
          TestType.SQLI,
          'excessive_data_exposure',
          'broken_access_control'
        ],
        attackParamLocations: [
          AttackParamLocation.BODY,
          AttackParamLocation.HEADER
        ]
      })
      .threshold(Severity.MEDIUM)
      .timeout(testTimeout)
      .run({
        method: 'POST',
        url: `${baseUrl}/articles/example-article/comments`,
        headers: {
          Authorization: 'Bearer <token>',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          comment: {
            body: 'This is a comment.'
          }
        })
      })

    t.end()
  })

  t.end()
})
