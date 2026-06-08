import * as better_auth_client from 'better-auth/client';
import * as better_auth_plugins_two_factor from 'better-auth/plugins/two-factor';
import * as better_auth_plugins_email_otp from 'better-auth/plugins/email-otp';
import * as better_auth from 'better-auth';
import * as better_auth_plugins_magic_link from 'better-auth/plugins/magic-link';
import * as better_call from 'better-call';
import * as zod_v4_core from 'zod/v4/core';
import * as zod from 'zod';
import { Hono, Context } from 'hono';
import { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types';

/**
 * Build the default Better Auth options used by SonicJS (through the CF shim).
 * Exported so apps can extend via config.auth.extendBetterAuth.
 */
declare function getDefaultAuthOptions(env: Bindings): {
    plugins: ({
        id: "magic-link";
        version: string;
        endpoints: {
            signInMagicLink: better_call.StrictEndpoint<"/sign-in/magic-link", {
                method: "POST";
                requireHeaders: true;
                body: zod.ZodObject<{
                    email: zod.ZodEmail;
                    name: zod.ZodOptional<zod.ZodString>;
                    callbackURL: zod.ZodOptional<zod.ZodString>;
                    newUserCallbackURL: zod.ZodOptional<zod.ZodString>;
                    errorCallbackURL: zod.ZodOptional<zod.ZodString>;
                    metadata: zod.ZodOptional<zod.ZodRecord<zod.ZodString, zod.ZodAny>>;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                status: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                status: boolean;
            }>;
            magicLinkVerify: better_call.StrictEndpoint<"/magic-link/verify", {
                method: "GET";
                query: zod.ZodObject<{
                    token: zod.ZodString;
                    callbackURL: zod.ZodOptional<zod.ZodString>;
                    errorCallbackURL: zod.ZodOptional<zod.ZodString>;
                    newUserCallbackURL: zod.ZodOptional<zod.ZodString>;
                }, zod_v4_core.$strip>;
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<void>)[];
                requireHeaders: true;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                session: {
                                                    $ref: string;
                                                };
                                                user: {
                                                    $ref: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                token: string;
                user: {
                    id: string;
                    createdAt: Date;
                    updatedAt: Date;
                    email: string;
                    emailVerified: boolean;
                    name: string;
                    image?: string | null | undefined;
                };
                session: {
                    id: string;
                    createdAt: Date;
                    updatedAt: Date;
                    userId: string;
                    expiresAt: Date;
                    token: string;
                    ipAddress?: string | null | undefined;
                    userAgent?: string | null | undefined;
                };
            }>;
        };
        rateLimit: {
            pathMatcher(path: string): boolean;
            window: number;
            max: number;
        }[];
        options: better_auth_plugins_magic_link.MagicLinkOptions;
    } | {
        id: "email-otp";
        version: string;
        init(ctx: better_auth.AuthContext): {
            options: {
                emailVerification: {
                    sendVerificationEmail(data: {
                        user: better_auth.User;
                        url: string;
                        token: string;
                    }, request: Request | undefined): Promise<void>;
                };
            };
        } | undefined;
        endpoints: {
            sendVerificationOTP: better_call.StrictEndpoint<"/email-otp/send-verification-otp", {
                method: "POST";
                body: zod.ZodObject<{
                    email: zod.ZodString;
                    type: zod.ZodEnum<{
                        "sign-in": "sign-in";
                        "change-email": "change-email";
                        "email-verification": "email-verification";
                        "forget-password": "forget-password";
                    }>;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                success: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                success: boolean;
            }>;
            createVerificationOTP: better_call.StrictEndpoint<string, {
                method: "POST";
                body: zod.ZodObject<{
                    email: zod.ZodString;
                    type: zod.ZodEnum<{
                        "sign-in": "sign-in";
                        "change-email": "change-email";
                        "email-verification": "email-verification";
                        "forget-password": "forget-password";
                    }>;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "string";
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, string>;
            getVerificationOTP: better_call.StrictEndpoint<string, {
                method: "GET";
                query: zod.ZodObject<{
                    email: zod.ZodString;
                    type: zod.ZodEnum<{
                        "sign-in": "sign-in";
                        "change-email": "change-email";
                        "email-verification": "email-verification";
                        "forget-password": "forget-password";
                    }>;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            "200": {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                otp: {
                                                    type: string;
                                                    nullable: boolean;
                                                    description: string;
                                                };
                                            };
                                            required: string[];
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                otp: null;
            } | {
                otp: string;
            }>;
            checkVerificationOTP: better_call.StrictEndpoint<"/email-otp/check-verification-otp", {
                method: "POST";
                body: zod.ZodObject<{
                    email: zod.ZodString;
                    type: zod.ZodEnum<{
                        "sign-in": "sign-in";
                        "change-email": "change-email";
                        "email-verification": "email-verification";
                        "forget-password": "forget-password";
                    }>;
                    otp: zod.ZodString;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                success: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                success: boolean;
            }>;
            verifyEmailOTP: better_call.StrictEndpoint<"/email-otp/verify-email", {
                method: "POST";
                body: zod.ZodObject<{
                    email: zod.ZodString;
                    otp: zod.ZodString;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                status: {
                                                    type: string;
                                                    description: string;
                                                    enum: boolean[];
                                                };
                                                token: {
                                                    type: string;
                                                    nullable: boolean;
                                                    description: string;
                                                };
                                                user: {
                                                    $ref: string;
                                                };
                                            };
                                            required: string[];
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                status: boolean;
                token: string;
                user: {
                    id: string;
                    createdAt: Date;
                    updatedAt: Date;
                    email: string;
                    emailVerified: boolean;
                    name: string;
                    image?: string | null | undefined;
                } & Record<string, any>;
            } | {
                status: boolean;
                token: null;
                user: {
                    id: string;
                    createdAt: Date;
                    updatedAt: Date;
                    email: string;
                    emailVerified: boolean;
                    name: string;
                    image?: string | null | undefined;
                } & Record<string, any>;
            }>;
            signInEmailOTP: better_call.StrictEndpoint<"/sign-in/email-otp", {
                method: "POST";
                body: zod.ZodIntersection<zod.ZodObject<{
                    email: zod.ZodString;
                    otp: zod.ZodString;
                    name: zod.ZodOptional<zod.ZodString>;
                    image: zod.ZodOptional<zod.ZodString>;
                }, zod_v4_core.$strip>, zod.ZodRecord<zod.ZodString, zod.ZodAny>>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                token: {
                                                    type: string;
                                                    description: string;
                                                };
                                                user: {
                                                    $ref: string;
                                                };
                                            };
                                            required: string[];
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                token: string;
                user: {
                    id: string;
                    createdAt: Date;
                    updatedAt: Date;
                    email: string;
                    emailVerified: boolean;
                    name: string;
                    image?: string | null | undefined;
                };
            }>;
            requestPasswordResetEmailOTP: better_call.StrictEndpoint<"/email-otp/request-password-reset", {
                method: "POST";
                body: zod.ZodObject<{
                    email: zod.ZodString;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                success: {
                                                    type: string;
                                                    description: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                success: boolean;
            }>;
            forgetPasswordEmailOTP: better_call.StrictEndpoint<"/forget-password/email-otp", {
                method: "POST";
                body: zod.ZodObject<{
                    email: zod.ZodString;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                success: {
                                                    type: string;
                                                    description: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                success: boolean;
            }>;
            resetPasswordEmailOTP: better_call.StrictEndpoint<"/email-otp/reset-password", {
                method: "POST";
                body: zod.ZodObject<{
                    email: zod.ZodString;
                    otp: zod.ZodString;
                    password: zod.ZodString;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                success: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                success: boolean;
            }>;
            requestEmailChangeEmailOTP: better_call.StrictEndpoint<"/email-otp/request-email-change", {
                method: "POST";
                body: zod.ZodObject<{
                    newEmail: zod.ZodString;
                    otp: zod.ZodOptional<zod.ZodString>;
                }, zod_v4_core.$strip>;
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                success: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                success: boolean;
            }>;
            changeEmailEmailOTP: better_call.StrictEndpoint<"/email-otp/change-email", {
                method: "POST";
                body: zod.ZodObject<{
                    newEmail: zod.ZodString;
                    otp: zod.ZodString;
                }, zod_v4_core.$strip>;
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                metadata: {
                    openapi: {
                        operationId: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                success: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                success: boolean;
            }>;
        };
        hooks: {
            after: {
                matcher(context: better_auth.HookEndpointContext): boolean;
                handler: (inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<void>;
            }[];
        };
        rateLimit: ({
            pathMatcher(path: string): path is "/email-otp/send-verification-otp";
            window: number;
            max: number;
        } | {
            pathMatcher(path: string): path is "/email-otp/check-verification-otp";
            window: number;
            max: number;
        } | {
            pathMatcher(path: string): path is "/email-otp/verify-email";
            window: number;
            max: number;
        } | {
            pathMatcher(path: string): path is "/sign-in/email-otp";
            window: number;
            max: number;
        } | {
            pathMatcher(path: string): path is "/email-otp/request-password-reset";
            window: number;
            max: number;
        } | {
            pathMatcher(path: string): path is "/email-otp/reset-password";
            window: number;
            max: number;
        } | {
            pathMatcher(path: string): path is "/forget-password/email-otp";
            window: number;
            max: number;
        } | {
            pathMatcher(path: string): path is "/email-otp/request-email-change";
            window: number;
            max: number;
        } | {
            pathMatcher(path: string): path is "/email-otp/change-email";
            window: number;
            max: number;
        })[];
        options: better_auth_plugins_email_otp.EmailOTPOptions;
        $ERROR_CODES: {
            OTP_EXPIRED: better_auth.RawError<"OTP_EXPIRED">;
            INVALID_OTP: better_auth.RawError<"INVALID_OTP">;
            TOO_MANY_ATTEMPTS: better_auth.RawError<"TOO_MANY_ATTEMPTS">;
        };
    } | {
        id: "two-factor";
        version: string;
        endpoints: {
            enableTwoFactor: better_call.StrictEndpoint<"/two-factor/enable", {
                method: "POST";
                body: zod.ZodObject<{
                    password: zod.ZodOptional<zod.ZodString>;
                    issuer: zod.ZodOptional<zod.ZodString>;
                }, zod_v4_core.$strip> | zod.ZodObject<{
                    password: zod.ZodString;
                    issuer: zod.ZodOptional<zod.ZodString>;
                }, zod_v4_core.$strip>;
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                metadata: {
                    openapi: {
                        summary: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                totpURI: {
                                                    type: string;
                                                    description: string;
                                                };
                                                backupCodes: {
                                                    type: string;
                                                    items: {
                                                        type: string;
                                                    };
                                                    description: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                totpURI: string;
                backupCodes: string[];
            }>;
            disableTwoFactor: better_call.StrictEndpoint<"/two-factor/disable", {
                method: "POST";
                body: zod.ZodObject<{
                    password: zod.ZodOptional<zod.ZodString>;
                }, zod_v4_core.$strip> | zod.ZodObject<{
                    password: zod.ZodString;
                }, zod_v4_core.$strip>;
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                metadata: {
                    openapi: {
                        summary: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                status: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                status: boolean;
            }>;
            verifyBackupCode: better_call.StrictEndpoint<"/two-factor/verify-backup-code", {
                method: "POST";
                body: zod.ZodObject<{
                    code: zod.ZodString;
                    disableSession: zod.ZodOptional<zod.ZodBoolean>;
                    trustDevice: zod.ZodOptional<zod.ZodBoolean>;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        description: string;
                        responses: {
                            "200": {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                user: {
                                                    type: string;
                                                    properties: {
                                                        id: {
                                                            type: string;
                                                            description: string;
                                                        };
                                                        email: {
                                                            type: string;
                                                            format: string;
                                                            nullable: boolean;
                                                            description: string;
                                                        };
                                                        emailVerified: {
                                                            type: string;
                                                            nullable: boolean;
                                                            description: string;
                                                        };
                                                        name: {
                                                            type: string;
                                                            nullable: boolean;
                                                            description: string;
                                                        };
                                                        image: {
                                                            type: string;
                                                            format: string;
                                                            nullable: boolean;
                                                            description: string;
                                                        };
                                                        twoFactorEnabled: {
                                                            type: string;
                                                            description: string;
                                                        };
                                                        createdAt: {
                                                            type: string;
                                                            format: string;
                                                            description: string;
                                                        };
                                                        updatedAt: {
                                                            type: string;
                                                            format: string;
                                                            description: string;
                                                        };
                                                    };
                                                    required: string[];
                                                    description: string;
                                                };
                                                session: {
                                                    type: string;
                                                    properties: {
                                                        token: {
                                                            type: string;
                                                            description: string;
                                                        };
                                                        userId: {
                                                            type: string;
                                                            description: string;
                                                        };
                                                        createdAt: {
                                                            type: string;
                                                            format: string;
                                                            description: string;
                                                        };
                                                        expiresAt: {
                                                            type: string;
                                                            format: string;
                                                            description: string;
                                                        };
                                                    };
                                                    required: string[];
                                                    description: string;
                                                };
                                            };
                                            required: string[];
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                token: string | undefined;
                user: (Record<string, any> & {
                    id: string;
                    createdAt: Date;
                    updatedAt: Date;
                    email: string;
                    emailVerified: boolean;
                    name: string;
                    image?: string | null | undefined;
                }) | better_auth_plugins_two_factor.UserWithTwoFactor;
            }>;
            generateBackupCodes: better_call.StrictEndpoint<"/two-factor/generate-backup-codes", {
                method: "POST";
                body: zod.ZodObject<{
                    password: zod.ZodOptional<zod.ZodString>;
                }, zod_v4_core.$strip> | zod.ZodObject<{
                    password: zod.ZodString;
                }, zod_v4_core.$strip>;
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                metadata: {
                    openapi: {
                        description: string;
                        responses: {
                            "200": {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                status: {
                                                    type: string;
                                                    description: string;
                                                    enum: boolean[];
                                                };
                                                backupCodes: {
                                                    type: string;
                                                    items: {
                                                        type: string;
                                                    };
                                                    description: string;
                                                };
                                            };
                                            required: string[];
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                status: boolean;
                backupCodes: string[];
            }>;
            viewBackupCodes: better_call.StrictEndpoint<string, {
                method: "POST";
                body: zod.ZodObject<{
                    userId: zod.ZodCoercedString<unknown>;
                }, zod_v4_core.$strip>;
            }, {
                status: boolean;
                backupCodes: string[];
            }>;
            sendTwoFactorOTP: better_call.StrictEndpoint<"/two-factor/send-otp", {
                method: "POST";
                body: zod.ZodOptional<zod.ZodObject<{
                    trustDevice: zod.ZodOptional<zod.ZodBoolean>;
                }, zod_v4_core.$strip>>;
                metadata: {
                    openapi: {
                        summary: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                status: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                status: boolean;
            }>;
            verifyTwoFactorOTP: better_call.StrictEndpoint<"/two-factor/verify-otp", {
                method: "POST";
                body: zod.ZodObject<{
                    code: zod.ZodString;
                    trustDevice: zod.ZodOptional<zod.ZodBoolean>;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        summary: string;
                        description: string;
                        responses: {
                            "200": {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                token: {
                                                    type: string;
                                                    description: string;
                                                };
                                                user: {
                                                    type: string;
                                                    properties: {
                                                        id: {
                                                            type: string;
                                                            description: string;
                                                        };
                                                        email: {
                                                            type: string;
                                                            format: string;
                                                            nullable: boolean;
                                                            description: string;
                                                        };
                                                        emailVerified: {
                                                            type: string;
                                                            nullable: boolean;
                                                            description: string;
                                                        };
                                                        name: {
                                                            type: string;
                                                            nullable: boolean;
                                                            description: string;
                                                        };
                                                        image: {
                                                            type: string;
                                                            format: string;
                                                            nullable: boolean;
                                                            description: string;
                                                        };
                                                        createdAt: {
                                                            type: string;
                                                            format: string;
                                                            description: string;
                                                        };
                                                        updatedAt: {
                                                            type: string;
                                                            format: string;
                                                            description: string;
                                                        };
                                                    };
                                                    required: string[];
                                                    description: string;
                                                };
                                            };
                                            required: string[];
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                token: string;
                user: better_auth_plugins_two_factor.UserWithTwoFactor;
            } | {
                token: string;
                user: Record<string, any> & {
                    id: string;
                    createdAt: Date;
                    updatedAt: Date;
                    email: string;
                    emailVerified: boolean;
                    name: string;
                    image?: string | null | undefined;
                };
            }>;
            generateTOTP: better_call.StrictEndpoint<string, {
                method: "POST";
                body: zod.ZodObject<{
                    secret: zod.ZodString;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        summary: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                code: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                code: string;
            }>;
            getTOTPURI: better_call.StrictEndpoint<"/two-factor/get-totp-uri", {
                method: "POST";
                use: ((inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    session: {
                        session: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            userId: string;
                            expiresAt: Date;
                            token: string;
                            ipAddress?: string | null | undefined;
                            userAgent?: string | null | undefined;
                        };
                        user: Record<string, any> & {
                            id: string;
                            createdAt: Date;
                            updatedAt: Date;
                            email: string;
                            emailVerified: boolean;
                            name: string;
                            image?: string | null | undefined;
                        };
                    };
                }>)[];
                body: zod.ZodObject<{
                    password: zod.ZodOptional<zod.ZodString>;
                }, zod_v4_core.$strip> | zod.ZodObject<{
                    password: zod.ZodString;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        summary: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                totpURI: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                totpURI: string;
            }>;
            verifyTOTP: better_call.StrictEndpoint<"/two-factor/verify-totp", {
                method: "POST";
                body: zod.ZodObject<{
                    code: zod.ZodString;
                    trustDevice: zod.ZodOptional<zod.ZodBoolean>;
                }, zod_v4_core.$strip>;
                metadata: {
                    openapi: {
                        summary: string;
                        description: string;
                        responses: {
                            200: {
                                description: string;
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object";
                                            properties: {
                                                status: {
                                                    type: string;
                                                };
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
            }, {
                token: string;
                user: better_auth_plugins_two_factor.UserWithTwoFactor;
            } | {
                token: string;
                user: Record<string, any> & {
                    id: string;
                    createdAt: Date;
                    updatedAt: Date;
                    email: string;
                    emailVerified: boolean;
                    name: string;
                    image?: string | null | undefined;
                };
            }>;
        };
        options: NoInfer<{
            issuer: string;
            totpOptions: {
                digits: 6;
                period: number;
            };
        }>;
        hooks: {
            after: {
                matcher(context: better_auth.HookEndpointContext): boolean;
                handler: (inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<{
                    twoFactorRedirect: boolean;
                    twoFactorMethods: string[];
                } | undefined>;
            }[];
        };
        schema: {
            user: {
                fields: {
                    twoFactorEnabled: {
                        type: "boolean";
                        required: false;
                        defaultValue: false;
                        input: false;
                    };
                };
            };
            twoFactor: {
                fields: {
                    secret: {
                        type: "string";
                        required: true;
                        returned: false;
                        index: true;
                    };
                    backupCodes: {
                        type: "string";
                        required: true;
                        returned: false;
                    };
                    userId: {
                        type: "string";
                        required: true;
                        returned: false;
                        references: {
                            model: string;
                            field: string;
                        };
                        index: true;
                    };
                    verified: {
                        type: "boolean";
                        required: false;
                        defaultValue: true;
                        input: false;
                    };
                };
            };
        };
        rateLimit: {
            pathMatcher(path: string): boolean;
            window: number;
            max: number;
        }[];
        $ERROR_CODES: {
            OTP_NOT_ENABLED: better_auth.RawError<"OTP_NOT_ENABLED">;
            OTP_HAS_EXPIRED: better_auth.RawError<"OTP_HAS_EXPIRED">;
            TOTP_NOT_ENABLED: better_auth.RawError<"TOTP_NOT_ENABLED">;
            TWO_FACTOR_NOT_ENABLED: better_auth.RawError<"TWO_FACTOR_NOT_ENABLED">;
            BACKUP_CODES_NOT_ENABLED: better_auth.RawError<"BACKUP_CODES_NOT_ENABLED">;
            INVALID_BACKUP_CODE: better_auth.RawError<"INVALID_BACKUP_CODE">;
            INVALID_CODE: better_auth.RawError<"INVALID_CODE">;
            TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE: better_auth.RawError<"TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE">;
            INVALID_TWO_FACTOR_COOKIE: better_auth.RawError<"INVALID_TWO_FACTOR_COOKIE">;
        };
    } | {
        id: "organization";
        version: string;
        endpoints: better_auth_client.OrganizationEndpoints<better_auth_client.OrganizationOptions & {
            teams: {
                enabled: true;
            };
            dynamicAccessControl?: {
                enabled?: false | undefined;
            } | undefined;
        }> & better_auth_client.TeamEndpoints<better_auth_client.OrganizationOptions & {
            teams: {
                enabled: true;
            };
            dynamicAccessControl?: {
                enabled?: false | undefined;
            } | undefined;
        }>;
        schema: better_auth_client.OrganizationSchema<better_auth_client.OrganizationOptions & {
            teams: {
                enabled: true;
            };
            dynamicAccessControl?: {
                enabled?: false | undefined;
            } | undefined;
        }>;
        $Infer: {
            Organization: {
                id: string;
                name: string;
                slug: string;
                createdAt: Date;
                logo?: string | null | undefined;
                metadata?: any;
            };
            Invitation: {
                id: string;
                organizationId: string;
                email: string;
                role: "admin" | "member" | "owner";
                status: better_auth_client.InvitationStatus;
                inviterId: string;
                expiresAt: Date;
                createdAt: Date;
                teamId?: string | undefined | undefined;
            };
            Member: {
                id: string;
                organizationId: string;
                role: "admin" | "member" | "owner";
                createdAt: Date;
                userId: string;
                teamId?: string | undefined | undefined;
                user: {
                    id: string;
                    email: string;
                    name: string;
                    image?: string | undefined;
                };
            };
            Team: {
                id: string;
                name: string;
                organizationId: string;
                createdAt: Date;
                updatedAt?: Date | undefined;
            };
            TeamMember: {
                id: string;
                teamId: string;
                userId: string;
                createdAt: Date;
            };
            ActiveOrganization: {
                members: {
                    id: string;
                    organizationId: string;
                    role: "admin" | "member" | "owner";
                    createdAt: Date;
                    userId: string;
                    teamId?: string | undefined | undefined;
                    user: {
                        id: string;
                        email: string;
                        name: string;
                        image?: string | undefined;
                    };
                }[];
                invitations: {
                    id: string;
                    organizationId: string;
                    email: string;
                    role: "admin" | "member" | "owner";
                    status: better_auth_client.InvitationStatus;
                    inviterId: string;
                    expiresAt: Date;
                    createdAt: Date;
                    teamId?: string | undefined | undefined;
                }[];
                teams: {
                    id: string;
                    name: string;
                    organizationId: string;
                    createdAt: Date;
                    updatedAt?: Date | undefined;
                }[];
            } & {
                id: string;
                name: string;
                slug: string;
                createdAt: Date;
                logo?: string | null | undefined;
                metadata?: any;
            };
        };
        $ERROR_CODES: {
            YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION">;
            YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS: better_auth.RawError<"YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS">;
            ORGANIZATION_ALREADY_EXISTS: better_auth.RawError<"ORGANIZATION_ALREADY_EXISTS">;
            ORGANIZATION_SLUG_ALREADY_TAKEN: better_auth.RawError<"ORGANIZATION_SLUG_ALREADY_TAKEN">;
            ORGANIZATION_NOT_FOUND: better_auth.RawError<"ORGANIZATION_NOT_FOUND">;
            USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION: better_auth.RawError<"USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION">;
            YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION">;
            YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION">;
            NO_ACTIVE_ORGANIZATION: better_auth.RawError<"NO_ACTIVE_ORGANIZATION">;
            USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION: better_auth.RawError<"USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION">;
            MEMBER_NOT_FOUND: better_auth.RawError<"MEMBER_NOT_FOUND">;
            ROLE_NOT_FOUND: better_auth.RawError<"ROLE_NOT_FOUND">;
            YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM">;
            TEAM_ALREADY_EXISTS: better_auth.RawError<"TEAM_ALREADY_EXISTS">;
            TEAM_NOT_FOUND: better_auth.RawError<"TEAM_NOT_FOUND">;
            YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER: better_auth.RawError<"YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER">;
            YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER: better_auth.RawError<"YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER">;
            YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER">;
            YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION">;
            USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION: better_auth.RawError<"USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION">;
            INVITATION_NOT_FOUND: better_auth.RawError<"INVITATION_NOT_FOUND">;
            YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION: better_auth.RawError<"YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION">;
            EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION: better_auth.RawError<"EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION">;
            EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION: better_auth.RawError<"EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION">;
            YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION">;
            INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION: better_auth.RawError<"INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION">;
            YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE">;
            FAILED_TO_RETRIEVE_INVITATION: better_auth.RawError<"FAILED_TO_RETRIEVE_INVITATION">;
            YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS: better_auth.RawError<"YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS">;
            UNABLE_TO_REMOVE_LAST_TEAM: better_auth.RawError<"UNABLE_TO_REMOVE_LAST_TEAM">;
            YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER">;
            ORGANIZATION_MEMBERSHIP_LIMIT_REACHED: better_auth.RawError<"ORGANIZATION_MEMBERSHIP_LIMIT_REACHED">;
            YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION">;
            YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION">;
            YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM">;
            YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM">;
            INVITATION_LIMIT_REACHED: better_auth.RawError<"INVITATION_LIMIT_REACHED">;
            TEAM_MEMBER_LIMIT_REACHED: better_auth.RawError<"TEAM_MEMBER_LIMIT_REACHED">;
            USER_IS_NOT_A_MEMBER_OF_THE_TEAM: better_auth.RawError<"USER_IS_NOT_A_MEMBER_OF_THE_TEAM">;
            YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM: better_auth.RawError<"YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM">;
            YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM: better_auth.RawError<"YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM">;
            YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER">;
            YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER">;
            YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION">;
            YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION: better_auth.RawError<"YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION">;
            MISSING_AC_INSTANCE: better_auth.RawError<"MISSING_AC_INSTANCE">;
            YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE: better_auth.RawError<"YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE">;
            YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE">;
            YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE">;
            YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE">;
            YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE">;
            YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE">;
            YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE: better_auth.RawError<"YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE">;
            TOO_MANY_ROLES: better_auth.RawError<"TOO_MANY_ROLES">;
            INVALID_RESOURCE: better_auth.RawError<"INVALID_RESOURCE">;
            ROLE_NAME_IS_ALREADY_TAKEN: better_auth.RawError<"ROLE_NAME_IS_ALREADY_TAKEN">;
            CANNOT_DELETE_A_PRE_DEFINED_ROLE: better_auth.RawError<"CANNOT_DELETE_A_PRE_DEFINED_ROLE">;
            ROLE_IS_ASSIGNED_TO_MEMBERS: better_auth.RawError<"ROLE_IS_ASSIGNED_TO_MEMBERS">;
            INVALID_TEAM_ID: better_auth.RawError<"INVALID_TEAM_ID">;
        };
        options: NoInfer<better_auth_client.OrganizationOptions & {
            teams: {
                enabled: true;
            };
            dynamicAccessControl?: {
                enabled?: false | undefined;
            } | undefined;
        }>;
    })[];
    socialProviders: {
        google?: {
            clientId: string;
            clientSecret: string;
        } | undefined;
        github?: {
            clientId: string;
            clientSecret: string;
        } | undefined;
    };
    user: {
        modelName: "users";
        fields: {
            image: string;
        };
        additionalFields: {
            role: {
                type: "string";
                required: false;
                defaultValue: string;
                input: false;
            };
            username: {
                type: "string";
                required: false;
                defaultValue: string;
                input: true;
            };
            firstName: {
                type: "string";
                required: false;
                defaultValue: string;
                input: true;
            };
            lastName: {
                type: "string";
                required: false;
                defaultValue: string;
                input: true;
            };
        };
    };
    session: {
        modelName: "session";
        expiresIn: number;
        updateAge: number;
    };
    account: {
        modelName: "account";
    };
    verification: {
        modelName: "verification";
    };
    basePath: string;
    emailAndPassword: {
        enabled: true;
        autoSignIn: true;
        password: {
            verify: ({ hash, password }: {
                hash: string;
                password: string;
            }) => Promise<boolean>;
        };
    };
    databaseHooks: {
        user: {
            create: {
                before: (userData: Record<string, unknown>) => Promise<{
                    data: {
                        name: string;
                        firstName: string;
                        lastName: string;
                        username: string;
                        role: string;
                    };
                }>;
                after: (user: {
                    id: string;
                }) => Promise<void>;
            };
        };
    };
    secret: string | undefined;
    baseURL: string | undefined;
    appName: string;
};
type BetterAuthDefaultOptions = ReturnType<typeof getDefaultAuthOptions>;
type ExtendBetterAuth = (opts: BetterAuthDefaultOptions) => BetterAuthDefaultOptions;

interface Bindings {
    DB: D1Database;
    CACHE_KV: KVNamespace;
    MEDIA_BUCKET: R2Bucket;
    ASSETS: Fetcher;
    EMAIL_QUEUE?: Queue;
    SENDGRID_API_KEY?: string;
    DEFAULT_FROM_EMAIL?: string;
    IMAGES_ACCOUNT_ID?: string;
    IMAGES_API_TOKEN?: string;
    ENVIRONMENT?: string;
    CORS_ORIGINS?: string;
    JWT_SECRET?: string;
    JWT_EXPIRES_IN?: string;
    JWT_REFRESH_GRACE_SECONDS?: string;
    BUCKET_NAME?: string;
    GOOGLE_MAPS_API_KEY?: string;
    BETTER_AUTH_SECRET?: string;
    BETTER_AUTH_URL?: string;
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
    GOOGLE_CLIENT_ID?: string;
    GOOGLE_CLIENT_SECRET?: string;
}
interface Variables {
    user?: {
        userId: string;
        email: string;
        role: string;
        exp: number;
        iat: number;
    };
    session?: {
        id: string;
        userId: string;
        token: string;
        expiresAt: number;
        createdAt: number;
        updatedAt: number;
    };
    requestId?: string;
    startTime?: number;
    appVersion?: string;
    csrfToken?: string;
    pluginMenuItems?: Array<{
        label: string;
        path: string;
        icon: string;
    }>;
    rbacPerms?: string[];
}
interface SonicJSConfig {
    collections?: {
        directory?: string;
        autoSync?: boolean;
    };
    plugins?: {
        directory?: string;
        autoLoad?: boolean;
        disableAll?: boolean;
    };
    routes?: Array<{
        path: string;
        handler: Hono;
    }>;
    middleware?: {
        beforeAuth?: Array<(c: Context, next: () => Promise<void>) => Promise<void>>;
        afterAuth?: Array<(c: Context, next: () => Promise<void>) => Promise<void>>;
    };
    auth?: {
        extendBetterAuth?: ExtendBetterAuth;
    };
    version?: string;
    name?: string;
}
type SonicJSApp = Hono<{
    Bindings: Bindings;
    Variables: Variables;
}>;
/**
 * Create a SonicJS application with core functionality
 *
 * @param config - Application configuration
 * @returns Configured Hono application
 *
 * @example
 * ```typescript
 * import { createSonicJSApp } from '@sonicjs-cms/core'
 *
 * const app = createSonicJSApp({
 *   collections: {
 *     directory: './src/collections',
 *     autoSync: true
 *   },
 *   plugins: {
 *     directory: './src/plugins',
 *     autoLoad: true
 *   }
 * })
 *
 * export default app
 * ```
 */
declare function createSonicJSApp(config?: SonicJSConfig): SonicJSApp;
/**
 * Setup core middleware (backward compatibility)
 *
 * @param _app - Hono application
 * @deprecated Use createSonicJSApp() instead
 */
declare function setupCoreMiddleware(_app: SonicJSApp): void;
/**
 * Setup core routes (backward compatibility)
 *
 * @param _app - Hono application
 * @deprecated Use createSonicJSApp() instead
 */
declare function setupCoreRoutes(_app: SonicJSApp): void;

export { type Bindings as B, type SonicJSConfig as S, type Variables as V, type SonicJSApp as a, setupCoreRoutes as b, createSonicJSApp as c, setupCoreMiddleware as s };
