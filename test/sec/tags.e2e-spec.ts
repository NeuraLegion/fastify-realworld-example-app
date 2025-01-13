import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../src/app.module';

let app: INestApplication;
let runner: SecRunner;

beforeAll(async () => {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleFixture.createNestApplication();
  await app.init();

  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
});

afterAll(async () => {
  await app.close();
  await runner.clear();
});

describe('GET /tags', () => {
  it('should not expose excessive data', async () => {
    const scan = runner.createScan({ tests: ['excessive_data_exposure'] });
    await scan.run({
      method: 'GET',
      url: 'http://localhost:3000/tags',
    });
  });

  it('should handle HTTP method fuzzing', async () => {
    const scan = runner.createScan({ tests: [TestType.HTTP_METHOD_FUZZING] });
    await scan.run({
      method: 'GET',
      url: 'http://localhost:3000/tags',
    });
  });
});
