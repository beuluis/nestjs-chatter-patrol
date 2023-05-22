[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]

<!-- PROJECT HEADER -->
<br />
<p align="center">
  <h3 align="center">nestjs-chatter-patrol</h3>

  <p align="center">
    Shared NestJS communication sanitation functionality
    <br />
    <br />
    ·
    <a href="https://github.com/beuluis/nestjs-chatter-patrol/issues">Report Bug</a>
    ·
    <a href="https://github.com/beuluis/nestjs-chatter-patrol/issues">Request Feature</a>
    ·
  </p>
</p>

<!-- ABOUT THE PROJECT -->

## About The Project

A collection of sanitation functionality for [NestJS](https://nestjs.com/).

Most functionality follows the `opt-out` principle. So you need to specifically whitelist stuff.

Another important design decision is to crash loudly, this avoid sanitation errors and issues happening unnoticed and posing a threat to your app´s integrity.

## Installation

```bash
npm i @beuluis/nestjs-chatter-patrol
```

### Unstable installation

The `next` dist-tag is kept in sync with the latest commit on main. So this contains always the latest changes but is highly unstable.

```bash
npm i @beuluis/nestjs-chatter-patrol@next
```

## Usage

```typescript
const app = await NestFactory.create(AppModule);
app.useGlobalInterceptors(new SanitizeInterceptor());
```

With custom logger:

```typescript
@Module({
    providers: [
        {
            provide: APP_INTERCEPTOR,
            inject: ['OtherLogger'],
            useFactory: (logger: OtherLogger) => new SanitizeInterceptor({ logger: logger }),
        },
    ],
})
```

### Whitelisting

> :warning: Whitelists get applied based on what the find methods matches first.

As example we use this config:

```typescript
new SanitizeInterceptor({
    whitelists: [
        {
            urlPath: '/exampleUrl',
            methods: 'all',
            scope: 'both',
            fields: ['exampleField', { fieldPath: /example/, allowedTags: ['b'] }],
        },
        {
            urlPath: /example/,
            methods: 'all',
            scope: 'both',
            whitelistAllContent: true,
        },
    ],
});
```

-   `curl -X POST -H "Content-Type: application/json" -d '{"exampleField": "value"}' http://example.com/exampleUrl` matches the first whitelist and `exampleField` gets not sanitized
-   `curl -X POST -H "Content-Type: application/json" -d '{"exampleOtherField": "value"}' http://example.com/exampleUrl` matches the first whitelist and `exampleOtherField` gets sanitized but `b` tags are allowed
-   `curl -X POST -H "Content-Type: text/plain" -d 'Hello' http://example.com/exampleOtherUrl` matches the second whitelist and nothing gets sanitized

#### Scope

-   Apply whitelist to `request`. See [interceptors](https://docs.nestjs.com/interceptors).

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        scope: 'request',
    }]});
    ```

-   Apply whitelist to `response`. See [interceptors](https://docs.nestjs.com/interceptors).

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        scope: 'response',
    }]});
    ```

-   Apply whitelist to `both`. See [interceptors](https://docs.nestjs.com/interceptors).

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        scope: 'both',
    }]});
    ```

#### URL path

-   Apply whitelist to `/example` url path.

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        urlPath: '/example',
    }]});
    ```

-   Apply whitelist to url paths matching `/example/`.

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        urlPath: /example/,
    }]});
    ```

#### Methods

-   Apply whitelist to `GET` and `POST` methods.

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        methods: ['GET', 'POST'],
    }]});
    ```

-   Apply whitelist to all methods.

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        methods: 'all',
    }]});
    ```

#### sanitizeOptions. See also [Whitelist with general sanitization configuration](#whitelist-with-general-sanitization-configuration)

-   To allow all `b` tags everywhere.

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        sanitizeOptions: {
            allowedTags: ['b'],
        },
    }]});
    ```

#### whitelistAllContent. See also [Whitelist with general sanitization configuration](#whitelist-with-general-sanitization-configuration)

-   Whitelist every content for matching `urlPath` and `methods`.

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        whitelistAllContent: true,
    }]});
    ```

#### fields. See also [Whitelist with additional field configuration](#whitelist-with-additional-field-configuration)

-   Whitelist the path `example.example`.

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        fields: ['example.example'],
    }]});
    ```

-   Whitelist the path matching `/example/`.

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        fields: [/example/],
    }]});
    ```

-   Apply sanitizeOptions to field path `example.example`

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        fields: [{
            fieldsPath: 'example.example',
            allowedTags: ['b'],
        }],
    }]});
    ```

-   Apply sanitizeOptions to field path matching `/example/`

    ```typescript
    new SanitizeInterceptor({ whitelists: [{
        ...,
        fields: ['example.[].example'],
    }]});
    ```

Whitelist field path in array element

## Interfaces

### SanitizeFieldOptions

-   `fieldPath` Defines which fields should not be sanitized.
-   `...` This interface also extends the option interface of [sanitize-html](https://www.npmjs.com/package/sanitize-html).

### Whitelist

-   `urlPath` Defines which url paths should not be sanitized. You can also use a regex here.
-   `methods` Defines which http methods should not be sanitized. Use 'all' to whitelist all methods.
-   `scope` Defines if the whitelist should be applied to the request, response or both

#### Whitelist with additional field configuration

-   `fields` Defines which fields should not be sanitized. Can be a string, regex or [SanitizeFieldOptions](#sanitizefieldoptions)

#### Whitelist with general sanitization configuration

-   `sanitizeOptions` Defines which options to be used for sanitization. Uses option interface of [sanitize-html](https://www.npmjs.com/package/sanitize-html).

#### Whitelist to ignore all content

-   `whitelistAllContent` Defines if you want to whitelist all content.

### SanitizeInterceptorOptions

-   `logger` Instance of the logger to be used. Defaults to @nestjs/common´s logger
-   `logLevel` Log level to be used when something unexpected fails. Defaults to 'warn'
-   `whitelist` Whitelist of paths, methods and fields to be ignored by the interceptor. Uses array of [Whitelist](#whitelist)

## Testing

Normally I would not test third party libs, but since this is such an important building block I follow a different approach to testing.

The test run the interceptor against multiple payloads compiled from known XSS payloads from github. Generally there are test that are probably too much, but hey much helps much. Right? RIGHT?

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- CONTACT -->

## Contact

Luis Beu - me@luisbeu.de

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/beuluis/nestjs-chatter-patrol.svg?style=flat-square
[contributors-url]: https://github.com/beuluis/nestjs-chatter-patrol/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/beuluis/nestjs-chatter-patrol.svg?style=flat-square
[forks-url]: https://github.com/beuluis/nestjs-chatter-patrol/network/members
[stars-shield]: https://img.shields.io/github/stars/beuluis/nestjs-chatter-patrol.svg?style=flat-square
[stars-url]: https://github.com/beuluis/nestjs-chatter-patrol/stargazers
[issues-shield]: https://img.shields.io/github/issues/beuluis/nestjs-chatter-patrol.svg?style=flat-square
[issues-url]: https://github.com/beuluis/nestjs-chatter-patrol/issues
[license-shield]: https://img.shields.io/github/license/beuluis/nestjs-chatter-patrol.svg?style=flat-square
