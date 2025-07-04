# K9
Your Cyber Hacker

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
