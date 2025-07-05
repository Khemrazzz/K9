# K9
Your Cyber Hacker... V1 <under dev>
Linux Pro Master ...V2  <Under research>
AI Powered Hacker...V3  <incoming>

## Prerequisites

- **JDK 21** – the build uses the Java 21 toolchain defined in `build.gradle`.
- **Gradle Wrapper** – use the provided `./gradlew` script inside the `HackerPlatform-Backend` directory.

## Building

From `HackerPlatform-Backend` run:

```bash
./gradlew build
```

This compiles the source and packages the jar under `build/libs/`.

## Running Tests

From `HackerPlatform-Backend` run:

```bash
./gradlew test
```

This executes the project's unit tests.

## Starting the Application

To start the Spring Boot application execute:

```bash
./gradlew bootRun
```

The service will start locally on the default port.

## Configuration

The backend expects a signing key through the `jwt.secret` property. During
development you can provide it by exporting an environment variable named
`JWT_SECRET` before starting the application:

```bash
export JWT_SECRET=<your-base64-secret>
./gradlew bootRun
```

Spring Boot automatically maps the `JWT_SECRET` variable to the `jwt.secret`
property so no additional configuration is required.

## Frontend Development

The Next.js UI lives under `HackerPlatform-UI`.

Before running the frontend you must tell it where the backend is located. Define
an `API_URL` environment variable pointing at your backend. The easiest way is
to create a `.env.local` file inside `HackerPlatform-UI` with the line:

```bash
API_URL=http://localhost:8080
```

Adjust the URL if your backend runs elsewhere.

Install dependencies once:

```bash
cd HackerPlatform-UI
npm install
```

During development run:

```bash
npm run dev
```

This starts the app locally with hot reload enabled.

### Configuring API_URL

API requests from the UI rely on the `API_URL` environment variable. Create a
`.env.local` file inside `HackerPlatform-UI` with the following contents:

```bash
API_URL=http://localhost:8080
```

Replace the URL with the address of your backend if different. With this file in
place run the development server:

```bash
npm run dev
```

You can also override the value directly on the command line:

```bash
API_URL=http://localhost:8080 npm run dev
```
