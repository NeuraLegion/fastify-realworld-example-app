'use strict'
const t = require('tap')
const { Configuration, SecRunner } = require('@sectester/runner')
const { TestType } = require('@sectester/scan')
const startServer = require('../setup-server')

const configuration = new Configuration({ hostname: 'app.brightsec.com' })

let runner

async function setupRunner() {
  runner = new SecRunner(configuration)
  await runner.init()
}

async function teardownRunner() {
  await runner.clear()
}

setupRunner()

// Test for the /profiles/johndoe endpoint

// Test for SQL Injection

// Test for Cross-Site Scripting (XSS)

// Test for Cross-Site Request Forgery (CSRF)

// Test for Broken Access Control

t.test('GET /profiles/johndoe', async t => {
  const server = await startServer()
  t.teardown(() => server.close())
  t.teardown(teardownRunner)

  const response = await server.inject({
    method: 'GET',
    url: '/profiles/johndoe',
    headers: {
      Authorization: 'Token optional_jwt_token'
    }
  })

  t.equal(response.statusCode, 200, 'returns a status code of 200 OK')

  const scan = runner.createScan({
    tests: [TestType.SQLI, TestType.XSS, TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL]
  })

  await scan.run({
    method: 'GET',
    url: 'http://localhost:3000/profiles/johndoe',
    headers: {
      Authorization: 'Token optional_jwt_token'
    }
  })

  t.end()
})
