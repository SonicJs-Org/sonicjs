// Global type definitions for SonicJS AI

// Cloudflare Workers environment bindings
interface CloudflareBindings {
  DB: D1Database;
  KV: KVNamespace;
  MEDIA_BUCKET: R2Bucket;
  EMAIL_QUEUE?: Queue;
  SENDGRID_API_KEY?: string;
  DEFAULT_FROM_EMAIL?: string;
  IMAGES_ACCOUNT_ID?: string;
  IMAGES_API_TOKEN?: string;
}

// User object shape used throughout the application
interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  avatar?: string;
  isActive: boolean;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// Auth middleware user object
interface AuthUser {
  userId: string;
  email: string;
  role: string;
  exp: number;
  iat: number;
}

// Email system types
interface EmailJob {
  id: string;
  type: 'templated' | 'direct';
  priority: 'low' | 'normal' | 'high';
  scheduledAt?: number;
  maxRetries: number;
  attemptCount: number;
  data: any;
  createdAt: number;
}

// Cloudflare Queue message batch
interface MessageBatch<T = any> {
  queue: string;
  messages: Array<{
    id: string;
    timestamp: Date;
    body: T;
    ack(): void;
    retry(): void;
  }>;
}

// Module declarations for external libraries
declare module 'marked' {
  export interface Renderer {
    heading(text: string, level: number): string;
    paragraph(text: string): string;
    link(href: string, title: string | null | undefined, text: string): string;
    strong(text: string): string;
    list(body: string, ordered: boolean): string;
    listitem(text: string): string;
    blockquote(quote: string): string;
    code(code: string, language?: string): string;
    codespan(code: string): string;
  }
  
  export class Renderer {
    heading(text: string, level: number): string;
    paragraph(text: string): string;
    link(href: string, title: string | null | undefined, text: string): string;
    strong(text: string): string;
    list(body: string, ordered: boolean): string;
    listitem(text: string): string;
    blockquote(quote: string): string;
    code(code: string, language?: string): string;
    codespan(code: string): string;
  }

  export function marked(src: string, options?: { renderer?: Renderer }): Promise<string>;
  export function setOptions(options: any): void;
}

declare module 'posthog-node' {
  export interface PostHogOptions {
    host?: string;
    flushAt?: number;
    flushInterval?: number;
  }

  export interface CaptureOptions {
    distinctId: string;
    event: string;
    properties?: Record<string, unknown>;
  }

  export class PostHog {
    constructor(apiKey: string, options?: PostHogOptions);
    capture(options: CaptureOptions): void;
    identify?(options: Record<string, unknown>): void;
    shutdown(): Promise<void>;
  }
}
