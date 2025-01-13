'use strict'
const t = require('tap')
const { SecRunner, TestType, Severity } = require('@sectester/runner')
const startServer = require('../setup-server')

const configuration = { hostname: 'app.brightsec.com' }

async function runSecurityTests() {
  const runner = new SecRunner(configuration)
  await runner.init()

  const scan = runner.createScan({
    tests: [
      TestType.BRUTE_FORCE_LOGIN,
      TestType.CSRF,
      TestType.EXCESSIVE_DATA_EXPOSURE,
      TestType.MASS_ASSIGNMENT,
      TestType.SQLI,
      TestType.XSS
    ],
    attackParamLocations: ['body', 'query', 'headers']
  })

  const target = {
    method: 'POST',
    url: 'http://localhost:3000/api/users',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user: {
        username: 'newuser',
        email: 'newuser@example.com',
        password: 'password123'
      }
    })
  }

  await scan.run(target)
  await runner.clear()
}

runSecurityTests().catch(err => {
  console.error('Security tests failed:', err)
})

// Example functional test

 t.test('get current user without login', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/api/user'
  })
  t.equal(response.statusCode, 401, 'returns a status code of 401 Unauthorized')
  t.end()
})
