# K9 web console

The Next.js console for K9. See the repository root README for setup, the session model and the tests.

```bash
npm ci
cp .env.example .env.local   # then fill in the secrets
npm run dev                  # http://localhost:3000
npm run check                # typecheck, lint, unit tests, production build
npm run test:e2e             # end-to-end tests; needs the stack running
```
