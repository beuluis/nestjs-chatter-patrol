import type { CallHandler, ExecutionContext, NestInterceptor } from '@nestjs/common';
import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import type { FastifyRequest, HTTPMethods } from 'fastify';
import type { Observable } from 'rxjs';
import { map } from 'rxjs';
import sanitizeHtml from 'sanitize-html';

type LogLevel = 'error' | 'warn';

type Path = RegExp | string;

type Scope = 'both' | 'request' | 'response';

export interface SanitizeFieldOptions extends sanitizeHtml.IOptions {
    /**
     * Defines which fields should not be sanitized
     */
    fieldPath: Path;
}

interface BaseWhitelist {
    /**
     * Defines which http methods should not be sanitized. Use 'all' to whitelist all methods
     */
    methods: HTTPMethods[] | 'all';
    /**
     * Defines if the whitelist should be applied to the request, response or both
     */
    scope: Scope;
    /**
     * Defines which url paths should not be sanitized
     */
    urlPath: Path;
}

interface WhitelistWithFields extends BaseWhitelist {
    /**
     * Defines which fields should not be sanitized
     */
    fields: Array<RegExp | SanitizeFieldOptions | string>;
    sanitizeOptions?: never;
    whitelistAllContent?: never;
}

interface WhitelistWithGeneralOptions extends BaseWhitelist {
    fields?: never;
    /**
     * Defines which options to be used for sanitization
     */
    sanitizeOptions: sanitizeHtml.IOptions;
    whitelistAllContent?: never;
}

interface WhitelistAllContentOptions extends BaseWhitelist {
    fields?: never;
    /**
     * Defines which options to be used for sanitization
     */
    sanitizeOptions?: never;
    /**
     * Defines if you want to whitelist all content
     */
    whitelistAllContent: true;
}

export type Whitelist =
    | WhitelistAllContentOptions
    | WhitelistWithFields
    | WhitelistWithGeneralOptions;

export interface SanitizeInterceptorOptions {
    /**
     * Log level to be used when something unexpected fails. Defaults to 'warn'
     */
    logLevel?: LogLevel;
    /**
     * Instance of the logger to be used. Defaults to @nestjs/common´s logger
     */
    logger?: Logger;
    /**
     * Whitelist of paths, methods and fields to be ignored by the interceptor
     */
    whitelists?: Whitelist[];
}

@Injectable()
export class SanitizeInterceptor implements NestInterceptor {
    private constructPath(currentPath: string, nextPathBit: string): string {
        // If the currentPath is empty, we can just return the nextPathBit
        if (currentPath === '') {
            return nextPathBit;
        }

        // If the currentPath is not empty, we need to concatenate it with the nextPathBit
        return `${currentPath}.${nextPathBit}`;
    }

    public constructor(options: SanitizeInterceptorOptions = {}) {
        // Get all from parameters or initialize with default values
        this.logger = options.logger ?? new Logger(SanitizeInterceptor.name);
        this.logLevel = options.logLevel ?? 'warn';

        // Concatenate all whitelists instead of overwriting them since we might want to set default whitelists
        this.whitelists = this.whitelists.concat(options.whitelists ?? []);
    }

    private handleError(error: unknown, path: string, method: string): never {
        if (error instanceof Error) {
            // Log the error
            this.logger[this.logLevel](
                `Error while sanitizing path: ${path} method: ${method}: ${error.message}`,
            );
            throw new InternalServerErrorException();
        }

        // Log unexpected errors
        this.logger[this.logLevel](
            `Unexpected error while sanitizing path: ${path} method: ${method}`,
        );
        throw new InternalServerErrorException();
    }

    // eslint-disable-next-line consistent-return -- It is a false positive
    public intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
        // Default values for path and method. They will be overwritten if the request is valid. Otherwise, they will be used to log the error and add context.
        let path = 'unknown';
        let method = 'unknown';

        try {
            // Get the request path and method
            // TODO: make it work optionally with express
            const request = context.switchToHttp().getRequest<FastifyRequest>();
            path = request.url;
            method = request.method;

            // Maybe sanitize the request body
            request.body = this.maybeSanitizeScope(request.body, path, method, 'request');

            return next.handle().pipe(
                // eslint-disable-next-line consistent-return -- It is a false positive
                map(data => {
                    try {
                        // Maybe sanitize the response body
                        return this.maybeSanitizeScope(data, path, method, 'response');
                    } catch (error) {
                        this.handleError(error, path, method);
                    }
                }),
            );
        } catch (error) {
            this.handleError(error, path, method);
        }
    }

    // Determines if the value is a SanitizeFieldOptions object to configure the sanitizeHtml function
    private isSanitizeFieldOptions(
        value: RegExp | SanitizeFieldOptions | string,
    ): value is SanitizeFieldOptions {
        return typeof value === 'object' && 'fieldPath' in value;
    }

    // Determines if the value is an object that should be sanitized. Null or Array are not considered objects in this case
    private isToSanitizedObject(value: unknown): value is Record<string, unknown> {
        return typeof value === 'object' && value !== null && !Array.isArray(value);
    }

    private readonly logLevel: LogLevel;

    private readonly logger: Logger;

    private matchesMethod(methods: HTTPMethods[] | 'all', methodToMatch: string): boolean {
        // If the methods is 'all', we can just return true
        if (methods === 'all') {
            return true;
        }

        // If the methods is an array, we need to check if the methodToMatch is included in it
        return methods.includes(methodToMatch as unknown as HTTPMethods);
    }

    private matchesPath(path: Path, pathToMatch: string): boolean {
        // If the urlPath is a string, we can just compare it to the urlPathToMatch
        if (typeof path === 'string') {
            return path === pathToMatch;
        }

        // If the urlPath is a RegExp, we need to test it against the urlPathToMatch
        return path.test(pathToMatch);
    }

    private matchesScope(scope: Scope, scopeToMatch: string): boolean {
        // If the scope is 'both', we can just return true
        if (scope === 'both') {
            return true;
        }

        // If the scope is not 'both', we need to check if it matches the scopeToMatch
        return scope === scopeToMatch;
    }

    private maybeSanitizeScope(
        data: unknown,
        urlPath: string,
        method: string,
        scope: Exclude<Scope, 'both'>,
    ): unknown {
        // Get the whitelist config to be applied
        const toApplyWhitelistConfig = this.whitelists.find(
            element =>
                // Check if the urlPath, method and scope match
                this.matchesPath(element.urlPath, urlPath) &&
                this.matchesMethod(element.methods, method) &&
                this.matchesScope(element.scope, scope),
        );

        // If all content is whitelisted, we can just return the data
        if (toApplyWhitelistConfig?.whitelistAllContent) {
            return data;
        }

        // If the data is an object, we need to sanitize it recursively
        if (this.isToSanitizedObject(data)) {
            return this.sanitizeObject(data, toApplyWhitelistConfig);
        }

        // If data is anything else, we sanitize it directly
        return this.sanitizeValue(data, toApplyWhitelistConfig);
    }

    // Recursive function to sanitize an object
    private sanitizeObject(
        object: Record<string, unknown>,
        whitelistConfig?: Whitelist,
        recursiveFieldPath = '',
    ): Record<string, unknown> {
        // Temporary object to store the sanitized values
        const sanitizedObject: Record<string, unknown> = {};

        for (const [key, value] of Object.entries(object)) {
            // Get the next path
            const thisFieldsPath = this.constructPath(recursiveFieldPath, key);

            if (
                // If the whitelistConfig is defined and the field is whitelisted, we skip it
                whitelistConfig?.fields?.some(
                    element =>
                        !this.isSanitizeFieldOptions(element) &&
                        this.matchesPath(element, thisFieldsPath),
                )
            ) {
                // Nothing to sanitize, just copy the value
                sanitizedObject[key] = value;
                continue;
            }

            // Sanitize the value
            sanitizedObject[key] = this.sanitizeValue(
                value,
                whitelistConfig,
                this.constructPath(recursiveFieldPath, thisFieldsPath),
            );
        }

        return sanitizedObject;
    }

    // Function to sanitize any value
    private sanitizeValue(
        value: unknown,
        whitelistConfig?: Whitelist,
        recursiveFieldPath = '',
    ): unknown {
        // If the value is a string, we sanitize it
        if (typeof value === 'string') {
            // Get the options to be used for sanitization
            const toApplySanitizeOptions =
                whitelistConfig?.sanitizeOptions ??
                whitelistConfig?.fields
                    ?.filter(this.isSanitizeFieldOptions) // Thank you typescript for this (not) amazing feature
                    .find(element => this.matchesPath(element.fieldPath, recursiveFieldPath)) ??
                {};

            // If the value is a string, we sanitize it
            return sanitizeHtml(value, {
                allowedTags: [],
                allowedAttributes: {},
                ...toApplySanitizeOptions,
            });
        } else if (Array.isArray(value)) {
            // If the value is an array, we sanitize each element
            for (let index = 0; index < value.length; index++) {
                // If the element is an object, we need to sanitize it recursively
                if (this.isToSanitizedObject(value[index])) {
                    value[index] = this.sanitizeObject(
                        value[index],
                        whitelistConfig,
                        this.constructPath(recursiveFieldPath, '[]'),
                    );
                    continue;
                }

                // If the element is any other type, we sanitize it as value
                value[index] = this.sanitizeValue(
                    value[index],
                    whitelistConfig,
                    recursiveFieldPath,
                );
            }
        } else if (this.isToSanitizedObject(value)) {
            // If the value is an object, we sanitize it recursively
            return this.sanitizeObject(value, whitelistConfig, recursiveFieldPath);
        }

        return value;
    }

    private readonly whitelists: Whitelist[] = [];
}
