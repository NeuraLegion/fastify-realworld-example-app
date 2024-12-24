import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { Server } from 'https';

const timeout = 600000;
jest.setTimeout(timeout);

let runner!: SecRunner;
let app!: INestApplication;
let baseUrl!: string;

beforeAll(async () => {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot()
    ]
  }).compile();

  app = moduleFixture.createNestApplication({
    logger: false
  });
  await app.init();

  const server = app.getHttpServer();

  server.listen(0);

  const port = server.address().port;
  const protocol = server instanceof Server ? 'https' : 'http';
  baseUrl = `${protocol}://localhost:${port}`;
});

afterAll(() => app.close());

beforeEach(async () => {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  runner = new SecRunner({ hostname: process.env.BRIGHT_HOSTNAME! });

  await runner.init();
});

afterEach(() => runner.clear());

describe('POST /api/users/login', () => {
  it('should not have SQLi', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [TestType.SQLI],
        attackParamLocations: [AttackParamLocation.BODY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'POST',
        url: `${baseUrl}/api/users/login`,
        headers: { 'Content-Type': 'application/json' },
        body: { user: { email: 'user@example.com', password: 'password123' } }
      });
  });

  it('should not have XSS', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [TestType.XSS],
        attackParamLocations: [AttackParamLocation.BODY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'POST',
        url: `${baseUrl}/api/users/login`,
        headers: { 'Content-Type': 'application/json' },
        body: { user: { email: 'user@example.com', password: 'password123' } }
      });
  });

  it('should not have CSRF', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [TestType.CSRF],
        attackParamLocations: [AttackParamLocation.BODY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'POST',
        url: `${baseUrl}/api/users/login`,
        headers: { 'Content-Type': 'application/json' },
        body: { user: { email: 'user@example.com', password: 'password123' } }
      });
  });
});
