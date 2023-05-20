/* eslint-disable unicorn/consistent-function-scoping */
/* eslint-disable jest/expect-expect */
/* eslint-disable jest/prefer-expect-assertions */
import type { CallHandler, ExecutionContext, Logger } from '@nestjs/common';
import { InternalServerErrorException } from '@nestjs/common';
import type { HttpArgumentsHost } from '@nestjs/common/interfaces';
import { mock } from 'jest-mock-extended';
import { lastValueFrom, of, throwError } from 'rxjs';
import type { Whitelist } from '../../src';
import { SanitizeInterceptor } from '../../src';

describe('SanitizeInterceptor', () => {
    const mockContext = mock<ExecutionContext>();
    const mockHandler = mock<CallHandler>();
    const mockLogger = mock<Logger>();
    let mockRequest = {} as { body: unknown; method: string; url: string };

    beforeEach(() => {
        mockRequest = {
            body: {},
            url: '/test',
            method: 'POST',
        };
        const mockHttp = {
            getRequest: () => mockRequest,
        } as HttpArgumentsHost;
        mockContext.switchToHttp.mockReturnValue(mockHttp);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    it('should initialize with default logger', () => {
        expect.assertions(1);

        const sanitizeInterceptorInstance = new SanitizeInterceptor();

        expect(sanitizeInterceptorInstance).toBeDefined();
    });

    const testRequestSanitization = (
        payload: unknown,
        expected: unknown,
        sanitizeInterceptorInstance = new SanitizeInterceptor({ logger: mockLogger }),
    ): void => {
        expect.assertions(1);

        mockRequest = {
            ...mockRequest,
            body: payload,
        };
        mockHandler.handle.mockReturnValueOnce(of({})); // Does not matter for request tests

        sanitizeInterceptorInstance.intercept(mockContext, mockHandler);

        expect(mockRequest.body).toEqual(expected);
    };

    const testResponseSanitization = async (
        payload: unknown,
        expected: unknown,
        sanitizeInterceptorInstance = new SanitizeInterceptor({ logger: mockLogger }),
    ): Promise<void> => {
        expect.assertions(1);

        mockHandler.handle.mockReturnValueOnce(of(payload));

        const observable = sanitizeInterceptorInstance.intercept(mockContext, mockHandler);

        const responseBody = await lastValueFrom(observable);

        expect(responseBody).toEqual(expected);
    };

    const testRequestResponseSanitization = async (
        requestPayload: unknown,
        requestExpected: unknown,
        responsePayload: unknown,
        responseExpected: unknown,
        sanitizeInterceptorInstance = new SanitizeInterceptor({ logger: mockLogger }),
    ): Promise<void> => {
        expect.assertions(2);

        mockRequest = {
            body: requestPayload,
            url: '/test',
            method: 'POST',
        };
        mockHandler.handle.mockReturnValueOnce(of(responsePayload));

        const observable = sanitizeInterceptorInstance.intercept(mockContext, mockHandler);

        const responseBody = await lastValueFrom(observable);

        expect(mockRequest.body).toEqual(requestExpected);
        expect(responseBody).toEqual(responseExpected);
    };

    describe('intercept', () => {
        const constructTestCases = (
            contextMessage: string,
            requestPayload: unknown,
            requestExpected: unknown,
            responsePayload: unknown,
            responseExpected: unknown,
        ) => {
            it(`${contextMessage} for request`, () => {
                testRequestSanitization(requestPayload, requestExpected);
            });

            it(`${contextMessage} for response`, async () => {
                await testResponseSanitization(responsePayload, responseExpected);
            });

            it(`${contextMessage} for both`, async () => {
                await testRequestResponseSanitization(
                    requestPayload,
                    requestExpected,
                    responsePayload,
                    responseExpected,
                );
            });
        };

        const interceptorPayloads = [
            {
                payload: '<svg/onload=location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`;//',
                expected: '',
            },
            { payload: '<svg><script>alert(1)<p>', expected: '' },
            { payload: '<svg><x><script>alert(1)</x>', expected: '' },
            { payload: `'';!--"<XSS>=&{()}`, expected: `'';!--"=&amp;{()}` },
            {
                payload: '<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>',
                expected: '',
            },
            { payload: `<IMG SRC="javascript:alert('XSS');">`, expected: '' },
            { payload: "<IMG SRC=javascript:alert('XSS')>", expected: '' },
            { payload: "<IMG SRC=JaVaScRiPt:alert('XSS')>", expected: '' },
            { payload: '<IMG SRC=javascript:alert("XSS")>', expected: '' },
            {
                payload: '<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>',
                expected: '',
            },
            {
                payload: '<a onmouseover="alert(document.cookie)">xxs link</a>',
                expected: 'xxs link',
            },
            {
                payload: '<a onmouseover=alert(document.cookie)>xxs link</a>',
                expected: 'xxs link',
            },
            {
                payload: '<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',
                expected: '"&gt;',
            },
            {
                payload: '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>',
                expected: '',
            },
            { payload: `<IMG SRC=# onmouseover="alert('xxs')">`, expected: '' },
            { payload: `<IMG SRC= onmouseover="alert('xxs')">`, expected: '' },
            { payload: `<IMG onmouseover="alert('xxs')">`, expected: '' },
            {
                payload: '<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>',
                expected: '',
            },
            {
                payload:
                    '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
                expected: '',
            },
            {
                payload:
                    '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>',
                expected: '',
            },
            {
                payload:
                    '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
                expected: '',
            },
            { payload: `<IMG SRC="jav\tascript:alert('XSS');">`, expected: '' },
            {
                payload: `<IMG SRC="jav&#x09;ascript:alert('XSS');">`,
                expected: '',
            },
            {
                payload: `<IMG SRC="jav&#x0A;ascript:alert('XSS');">`,
                expected: '',
            },
            {
                payload: `<IMG SRC="jav&#x0D;ascript:alert('XSS');">`,
                expected: '',
            },
            {
                payload: `<IMG SRC=" &#14;  javascript:alert('XSS');">`,
                expected: '',
            },
            {
                payload: '<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>',
                expected: '',
            },
            {
                payload: '<BODY onload!#$%&()*~+-_.,:;?@[/|]^`=alert("XSS")>',
                expected: '',
            },
            {
                payload: '<SCRIPT/SRC="http://ha.ckers.org/xss.js"></SCRIPT>',
                expected: '',
            },
            { payload: '<<SCRIPT>alert("XSS");//<</SCRIPT>', expected: '&lt;' },
            {
                payload: '<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >',
                expected: '',
            },
            { payload: '<SCRIPT SRC=//ha.ckers.org/.j>', expected: '' },
            { payload: `<IMG SRC="javascript:alert('XSS')"`, expected: '' },
            {
                payload: '<iframe src=http://ha.ckers.org/scriptlet.html <',
                expected: '',
            },
            { payload: `";alert('XSS');//`, expected: `";alert('XSS');//` },
            { payload: '</TITLE><SCRIPT>alert("XSS");</SCRIPT>', expected: '' },
            {
                payload: `<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">`,
                expected: '',
            },
            {
                payload: `<BODY BACKGROUND="javascript:alert('XSS')">`,
                expected: '',
            },
            { payload: `<IMG DYNSRC="javascript:alert('XSS')">`, expected: '' },
            { payload: `<IMG LOWSRC="javascript:alert('XSS')">`, expected: '' },
            {
                payload: `<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>`,
                expected: 'XSS',
            },
            { payload: `<IMG SRC='vbscript:msgbox("XSS")'>`, expected: '' },
            { payload: '<IMG SRC="livescript:[code]">', expected: '' },
            { payload: "<BODY ONLOAD=alert('XSS')>", expected: '' },
            {
                payload: { test: true, test2: 1, test3: null, test4: undefined },
                expected: { test: true, test2: 1, test3: null, test4: undefined },
            },
        ];

        for (const { payload, expected } of interceptorPayloads) {
            constructTestCases(
                `should sanitize '${JSON.stringify(payload)}' to '${JSON.stringify(
                    expected,
                )}' in object`,
                { test: payload },
                { test: expected },
                { test: payload },
                { test: expected },
            );

            constructTestCases(
                `should sanitize '${JSON.stringify(payload)}' to '${JSON.stringify(
                    expected,
                )}' in nested object`,
                { test: { test: payload } },
                { test: { test: expected } },
                { test: { test: payload } },
                { test: { test: expected } },
            );

            constructTestCases(
                `should sanitize '${JSON.stringify(payload)}' to '${JSON.stringify(
                    expected,
                )}' in nested array`,
                { test: [payload] },
                { test: [expected] },
                { test: [payload] },
                { test: [expected] },
            );

            constructTestCases(
                `should sanitize '${JSON.stringify(payload)}' to '${JSON.stringify(
                    expected,
                )}' in nested array with object`,
                { test: [{ test: payload }] },
                { test: [{ test: expected }] },
                { test: [{ test: payload }] },
                { test: [{ test: expected }] },
            );

            constructTestCases(
                `should sanitize '${JSON.stringify(payload)}' to '${JSON.stringify(
                    expected,
                )}' in array`,
                [payload],
                [expected],
                [payload],
                [expected],
            );

            constructTestCases(
                `should sanitize '${JSON.stringify(payload)}' to '${JSON.stringify(
                    expected,
                )}' in plain value`,
                payload,
                expected,
                payload,
                expected,
            );
        }
    });

    describe('intercept - whitelisting', () => {
        const constructTestCases = (
            contextMessage: string,
            requestPayload: unknown,
            requestExpected: unknown,
            responsePayload: unknown,
            responseExpected: unknown,
            whitelist: Omit<Whitelist, 'scope'>,
        ) => {
            it(`${contextMessage} for request`, () => {
                testRequestSanitization(
                    requestPayload,
                    requestExpected,
                    new SanitizeInterceptor({
                        logger: mockLogger,
                        whitelists: [{ ...whitelist, scope: 'request' } as unknown as Whitelist],
                    }),
                );
            });

            it(`${contextMessage} for response`, async () => {
                await testResponseSanitization(
                    responsePayload,
                    responseExpected,
                    new SanitizeInterceptor({
                        logger: mockLogger,
                        whitelists: [{ ...whitelist, scope: 'response' } as unknown as Whitelist],
                    }),
                );
            });

            it(`${contextMessage} for both`, async () => {
                await testRequestResponseSanitization(
                    requestPayload,
                    requestExpected,
                    responsePayload,
                    responseExpected,
                    new SanitizeInterceptor({
                        logger: mockLogger,
                        whitelists: [{ ...whitelist, scope: 'both' } as unknown as Whitelist],
                    }),
                );
            });
        };

        const interceptorShouldNotTouchWhitelistPayloads = [
            { test: 'test<img />' },
            { test: { test: 'test<img />' } },
            { test: ['test<img />'] },
            { test: [{ test: 'test<img />' }] },
            ['test<img />'],
            'test<img />',
        ];

        // Test if all ignore cases are working. Payload and expect should always be the same for those cases
        for (const payload of interceptorShouldNotTouchWhitelistPayloads) {
            constructTestCases(
                `should not sanitize ${JSON.stringify(payload)} when urlPath matches whitelist`,
                payload,
                payload,
                payload,
                payload,
                {
                    urlPath: '/test',
                    methods: 'all',
                    whitelistAllContent: true,
                },
            );

            constructTestCases(
                `should not sanitize ${JSON.stringify(
                    payload,
                )} when urlPath matches regex whitelist`,
                payload,
                payload,
                payload,
                payload,
                {
                    urlPath: /test/u,
                    methods: 'all',
                    whitelistAllContent: true,
                },
            );

            constructTestCases(
                `should not sanitize ${JSON.stringify(payload)} when methods matches whitelist`,
                payload,
                payload,
                payload,
                payload,
                {
                    urlPath: '/test',
                    methods: ['POST'],
                    whitelistAllContent: true,
                },
            );

            constructTestCases(
                `should not sanitize ${JSON.stringify(payload)} when methods matches whitelist`,
                payload,
                payload,
                payload,
                payload,
                {
                    urlPath: '/test',
                    methods: ['POST'],
                    whitelistAllContent: true,
                },
            );

            constructTestCases(
                `should not sanitize ${JSON.stringify(
                    payload,
                )} anything when whitelistAllContent is true`,
                payload,
                payload,
                payload,
                payload,
                {
                    urlPath: '/test',
                    methods: 'all',
                    whitelistAllContent: true,
                },
            );
        }

        const interceptorShouldApplySanitizeOptionsPayloads = [
            { payload: { test: 'test<img /><br />' }, expected: { test: 'test<img />' } },
            {
                payload: { test: { test: 'test<img /><br />' } },
                expected: { test: { test: 'test<img />' } },
            },
            { payload: { test: ['test<img /><br />'] }, expected: { test: ['test<img />'] } },
            {
                payload: { test: [{ test: 'test<img /><br />' }] },
                expected: { test: [{ test: 'test<img />' }] },
            },
            { payload: ['test<img /><br />'], expected: ['test<img />'] },
            { payload: 'test<img /><br />', expected: 'test<img />' },
        ];

        for (const { payload, expected } of interceptorShouldApplySanitizeOptionsPayloads) {
            constructTestCases(
                `should apply sanitizeOptions to ${JSON.stringify(
                    payload,
                )} resulting in ${JSON.stringify(expected)}`,
                payload,
                expected,
                payload,
                expected,
                {
                    urlPath: '/test',
                    methods: 'all',
                    sanitizeOptions: {
                        allowedTags: ['img'],
                    },
                },
            );
        }

        constructTestCases(
            'should not sanitize when field path is matching whitelist',
            { test: 'test<img />', test2: 'test<img />' },
            { test: 'test<img />', test2: 'test' },
            { test: 'test<img />', test2: 'test<img />' },
            { test: 'test<img />', test2: 'test' },
            {
                urlPath: '/test',
                methods: 'all',
                fields: ['test'],
            },
        );

        constructTestCases(
            'should apply sanitizeOptions when field path is matching whitelist',
            { test: 'test<img /><br>', test2: 'test<img /><br>' },
            { test: 'test<img />', test2: 'test' },
            { test: 'test<img /><br>', test2: 'test<img /><br>' },
            { test: 'test<img />', test2: 'test' },
            {
                urlPath: '/test',
                methods: 'all',
                fields: [{ fieldPath: 'test', allowedTags: ['img'] }],
            },
        );

        constructTestCases(
            'should not sanitize when field path is matching regex whitelist',
            { test: 'test<img />', test2: 'test<img />', abc: 'test<img />' },
            { test: 'test<img />', test2: 'test<img />', abc: 'test' },
            { test: 'test<img />', test2: 'test<img />', abc: 'test<img />' },
            { test: 'test<img />', test2: 'test<img />', abc: 'test' },
            {
                urlPath: '/test',
                methods: 'all',
                fields: [/test/u],
            },
        );

        constructTestCases(
            'should apply sanitizeOptions when field path is matching regex whitelist',
            { test: 'test<img /><br>', test2: 'test<img /><br>', abc: 'test<img /><br>' },
            { test: 'test<img />', test2: 'test<img />', abc: 'test' },
            { test: 'test<img /><br>', test2: 'test<img /><br>', abc: 'test<img /><br>' },
            { test: 'test<img />', test2: 'test<img />', abc: 'test' },
            {
                urlPath: '/test',
                methods: 'all',
                fields: [{ fieldPath: /test/u, allowedTags: ['img'] }],
            },
        );

        constructTestCases(
            'should not sanitize when field path is matching in tested array with object whitelist',
            { test: [{ test: 'test<img />', test2: 'test<img />' }] },
            { test: [{ test: 'test<img />', test2: 'test' }] },
            { test: [{ test: 'test<img />', test2: 'test<img />' }] },
            { test: [{ test: 'test<img />', test2: 'test' }] },
            {
                urlPath: '/test',
                methods: 'all',
                fields: ['test.[].test'],
            },
        );

        constructTestCases(
            'should not sanitize when field path is matching in array object whitelist',
            [{ test: 'test<img />', test2: 'test<img />' }],
            [{ test: 'test<img />', test2: 'test' }],
            [{ test: 'test<img />', test2: 'test<img />' }],
            [{ test: 'test<img />', test2: 'test' }],
            {
                urlPath: '/test',
                methods: 'all',
                fields: ['[].test'],
            },
        );
    });

    describe('intercept - catch', () => {
        it('should throw InternalServerErrorException and log when unexpected error occurs when request is retrieved and path and method is unknown', () => {
            expect.assertions(2);
            const mockHttp = {
                getRequest: () => {
                    throw new Error('Unexpected error');
                },
            } as unknown as HttpArgumentsHost;
            mockContext.switchToHttp.mockReturnValue(mockHttp);

            expect(() =>
                new SanitizeInterceptor({ logger: mockLogger }).intercept(mockContext, mockHandler),
            ).toThrow(InternalServerErrorException);

            expect(mockLogger.warn).toHaveBeenCalledWith(
                'Error while sanitizing path: unknown method: unknown: Unexpected error',
            );
        });

        it('should throw InternalServerErrorException and log when unexpected error occurs after request is retrieved and path and method is known', () => {
            expect.assertions(2);

            const sanitizeInterceptor = new SanitizeInterceptor({ logger: mockLogger });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            jest.spyOn(sanitizeInterceptor as any, 'sanitizeObject').mockImplementation(() => {
                throw new Error('Unexpected error');
            });

            expect(() => sanitizeInterceptor.intercept(mockContext, mockHandler)).toThrow(
                InternalServerErrorException,
            );

            expect(mockLogger.warn).toHaveBeenCalledWith(
                'Error while sanitizing path: /test method: POST: Unexpected error',
            );
        });

        it('should throw InternalServerErrorException and log when unexpected error when error is not instance of error', () => {
            expect.assertions(2);

            const sanitizeInterceptor = new SanitizeInterceptor({ logger: mockLogger });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            jest.spyOn(sanitizeInterceptor as any, 'sanitizeObject').mockImplementation(() => {
                // eslint-disable-next-line @typescript-eslint/no-throw-literal
                throw 'Unexpected error';
            });

            expect(() => sanitizeInterceptor.intercept(mockContext, mockHandler)).toThrow(
                InternalServerErrorException,
            );

            expect(mockLogger.warn).toHaveBeenCalledWith(
                'Unexpected error while sanitizing path: /test method: POST',
            );
        });

        it('should throw InternalServerErrorException and log when response has an unexpected error', async () => {
            expect.assertions(2);

            mockHandler.handle.mockReturnValueOnce(of({}));

            const sanitizeInterceptor = new SanitizeInterceptor({
                logger: mockLogger,
                whitelists: [
                    {
                        urlPath: '/test',
                        methods: ['POST'],
                        whitelistAllContent: true,
                        scope: 'request', // Whitelist request that the spy on does trigger only for response
                    },
                ],
            });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            jest.spyOn(sanitizeInterceptor as any, 'sanitizeObject').mockImplementation(() => {
                throw new Error('Unexpected error');
            });

            const observable = sanitizeInterceptor.intercept(mockContext, mockHandler);

            await expect(lastValueFrom(observable)).rejects.toThrow(InternalServerErrorException);
            expect(mockLogger.warn).toHaveBeenCalledWith(
                'Error while sanitizing path: /test method: POST: Unexpected error',
            );
        });

        it('should throw InternalServerErrorException and log when unexpected error as log level error', () => {
            expect.assertions(2);

            const sanitizeInterceptor = new SanitizeInterceptor({
                logger: mockLogger,
                logLevel: 'error',
            });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            jest.spyOn(sanitizeInterceptor as any, 'sanitizeObject').mockImplementation(() => {
                throw new Error('Unexpected error');
            });

            expect(() => sanitizeInterceptor.intercept(mockContext, mockHandler)).toThrow(
                InternalServerErrorException,
            );
            expect(mockLogger.error).toHaveBeenCalledWith(
                'Error while sanitizing path: /test method: POST: Unexpected error',
            );
        });

        it('should not touch errors not thrown by sanitization', async () => {
            expect.assertions(2);

            mockHandler.handle.mockReturnValueOnce(
                throwError(() => new Error('Unexpected controller error')),
            );

            const observable = new SanitizeInterceptor({ logger: mockLogger }).intercept(
                mockContext,
                mockHandler,
            );

            await expect(lastValueFrom(observable)).rejects.toThrow(
                new Error('Unexpected controller error'),
            );
            expect(mockLogger.warn).not.toHaveBeenCalled();
        });
    });
});
