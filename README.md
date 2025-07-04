# K9
Your Cyber Hacker

## Prerequisites

- **JDK 24** – the build uses the Java 24 toolchain defined in `build.gradle`.
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

## Frontend Development

The Next.js UI lives under `HackerPlatform-UI`.

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

Replace the URL with the address of your backend if different. The Next.js app
will pick up this variable when you run `npm run dev`.
