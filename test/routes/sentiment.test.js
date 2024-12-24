'use strict'
const t = require('tap');
const { Configuration, SecRunner } = require('@sectester/runner');
const { TestType, Severity } = require('@sectester/scan');
const startServer = require('../setup-server');

const configuration = new Configuration({ hostname: 'app.brightsec.com' });

const runSecurityTests = async () => {
  const runner = new SecRunner(configuration);
  await runner.init();

  const scan = runner.createScan({
    tests: [TestType.XSS, TestType.SQLI],
    threshold: Severity.MEDIUM,
    timeout: 300000, // 5 minutes
  });

  const server = await startServer();
  const response = await server.inject({
    method: 'POST',
    url: '/sentiment/score',
    headers: { 'Content-Type': 'application/json' },
    payload: { content: 'string' },
  });

  await scan.run({
    method: 'POST',
    url: 'http://localhost:3000/sentiment/score',
    body: { content: 'string' },
  });

  await runner.clear();
  server.close();
};

runSecurityTests().catch((err) => console.error(err));
