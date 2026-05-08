import { EmailTemplate, EmailTheme } from '../schema';
import { renderTemplate } from '../../../../utils';
import { marked, Renderer } from 'marked';

export interface EmailRenderResult {
  html: string;
  text: string;
  subject: string;
}

export interface EmailVariables {
  [key: string]: any;
}

export class EmailTemplateRenderer {
  constructor(private db: any) {}

  async renderTemplate(
    templateSlug: string, 
    variables: EmailVariables = {}
  ): Promise<EmailRenderResult> {
    // Get template and theme
    const template = await this.getTemplateBySlug(templateSlug);
    if (!template) {
      throw new Error(`Email template not found: ${templateSlug}`);
    }

    const theme = await this.getThemeById(template.themeId);
    if (!theme) {
      throw new Error(`Email theme not found: ${template.themeId}`);
    }

    // Merge system variables with provided variables
    const allVariables = {
      ...this.getSystemVariables(),
      ...this.parseJsonField(template.variables as string | null),
      ...variables,
    };

    // Render markdown content to HTML
    const bodyHtml = await this.renderMarkdownToHtml(template.markdownContent, allVariables);
    
    // Render the full email HTML using the theme
    const emailHtml = this.renderEmailHtml(theme, bodyHtml, allVariables);

    // Generate plain text version
    const textContent = this.htmlToText(emailHtml);

    // Render subject line
    const subject = renderTemplate(template.subject, allVariables);

    return {
      html: emailHtml,
      text: textContent,
      subject,
    };
  }

  private async getTemplateBySlug(slug: string): Promise<EmailTemplate | null> {
    try {
      const stmt = this.db.prepare('SELECT * FROM email_templates WHERE slug = ? AND is_active = 1');
      const result = await stmt.bind(slug).first();
      return result || null;
    } catch (error) {
      console.error('Failed to get email template:', error);
      return null;
    }
  }

  private async getThemeById(id: string): Promise<EmailTheme | null> {
    try {
      const stmt = this.db.prepare('SELECT * FROM email_themes WHERE id = ? AND is_active = 1');
      const result = await stmt.bind(id).first();
      return result || null;
    } catch (error) {
      console.error('Failed to get email theme:', error);
      return null;
    }
  }

  private getSystemVariables(): EmailVariables {
    const now = new Date();
    return {
      site: {
        name: 'SonicJS AI',
        url: 'https://sonicjs-ai.com',
        logo: '/favicon.svg',
      },
      date: {
        now: now.toISOString().split('T')[0],
        year: now.getFullYear().toString(),
        month: (now.getMonth() + 1).toString().padStart(2, '0'),
        day: now.getDate().toString().padStart(2, '0'),
      },
      email: {
        unsubscribeUrl: '{{unsubscribe_url}}', // Will be replaced by actual unsubscribe logic
        preferencesUrl: '{{preferences_url}}',
      },
    };
  }

  private async renderMarkdownToHtml(markdown: string, variables: EmailVariables): Promise<string> {
    // First, apply variable substitution to the markdown
    const processedMarkdown = renderTemplate(markdown, variables);

    // Custom renderer for email-friendly output
    const renderer = new Renderer();
    
    // Customize link rendering for email safety
    renderer.link = (href: string, title: string | null | undefined, text: string) => {
      const titleAttr = title ? ` title="${title}"` : '';
      return `<a href="${href}"${titleAttr} style="color: #8b5cf6; text-decoration: none;">${text}</a>`;
    };

    // Customize button/call-to-action styling
    renderer.strong = (text: string) => {
      // Check if this might be a button-like element
      if (text.toLowerCase().includes('button') || 
          text.toLowerCase().includes('click') ||
          text.toLowerCase().includes('get started') ||
          text.toLowerCase().includes('reset password') ||
          text.toLowerCase().includes('confirm') ||
          text.toLowerCase().includes('activate')) {
        return `<strong style="display: inline-block; background: linear-gradient(135deg, #8b5cf6 0%, #06b6d4 100%); color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 8px 0;">${text}</strong>`;
      }
      return `<strong style="color: #111827;">${text}</strong>`;
    };

    // Add email-friendly styles to headings
    renderer.heading = (text: string, level: number) => {
      const styles = {
        1: 'font-size: 32px; color: #111827; margin: 0 0 20px 0; font-weight: 600; line-height: 1.3;',
        2: 'font-size: 24px; color: #374151; margin: 32px 0 16px 0; font-weight: 600; line-height: 1.3;',
        3: 'font-size: 20px; color: #374151; margin: 24px 0 12px 0; font-weight: 600; line-height: 1.3;',
        4: 'font-size: 18px; color: #4b5563; margin: 20px 0 8px 0; font-weight: 600; line-height: 1.3;',
        5: 'font-size: 16px; color: #4b5563; margin: 16px 0 8px 0; font-weight: 600; line-height: 1.3;',
        6: 'font-size: 14px; color: #4b5563; margin: 12px 0 8px 0; font-weight: 600; line-height: 1.3;',
      };
      const style = styles[level as keyof typeof styles] || styles[6];
      return `<h${level} style="${style}">${text}</h${level}>`;
    };

    // Add email-friendly styles to paragraphs
    renderer.paragraph = (text: string) => {
      return `<p style="margin: 0 0 16px 0; font-size: 16px; line-height: 1.6; color: #374151;">${text}</p>`;
    };

    // Style lists for email
    renderer.list = (body: string, ordered: boolean) => {
      const tag = ordered ? 'ol' : 'ul';
      const style = 'margin: 0 0 16px 0; padding-left: 24px;';
      return `<${tag} style="${style}">${body}</${tag}>`;
    };

    renderer.listitem = (text: string) => {
      return `<li style="margin-bottom: 8px; color: #374151;">${text}</li>`;
    };

    // Style blockquotes for email
    renderer.blockquote = (quote: string) => {
      return `<blockquote style="border-left: 4px solid #8b5cf6; padding-left: 20px; margin: 20px 0; font-style: italic; color: #4b5563; background-color: #f8fafc; padding: 16px 20px; border-radius: 0 8px 8px 0;">${quote}</blockquote>`;
    };

    // Style code for email
    renderer.code = (code: string, _language?: string) => {
      return `<pre style="background-color: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; margin: 20px 0; font-family: Monaco, Menlo, Ubuntu Mono, monospace;"><code>${code}</code></pre>`;
    };

    renderer.codespan = (code: string) => {
      return `<code style="background-color: #f1f5f9; color: #8b5cf6; padding: 2px 6px; border-radius: 4px; font-family: Monaco, Menlo, Ubuntu Mono, monospace; font-size: 14px;">${code}</code>`;
    };

    // Convert markdown to HTML using the custom renderer
    const html = await marked(processedMarkdown, { 
      renderer
    });

    return html;
  }

  private renderEmailHtml(theme: EmailTheme, bodyHtml: string, variables: EmailVariables): string {
    // Parse theme variables
    const themeVariables = this.parseJsonField(theme.variables as string | null);
    
    // Combine all variables for theme rendering
    const allVariables = {
      ...variables,
      ...themeVariables,
      email_content: bodyHtml,
      theme_styles: theme.cssStyles,
    };

    // Render the theme template
    return renderTemplate(theme.htmlTemplate, allVariables);
  }

  private htmlToText(html: string): string {
    // Simple HTML to text conversion
    // In production, consider using a library like html-to-text
    let result = html
      .replace(/<style[^>]*>.*?<\/style>/gis, '') // Remove style tags
      .replace(/<script[^>]*>.*?<\/script>/gis, '') // Remove script tags
      .replace(/<\/?(p|div|h[1-6]|br)[^>]*>/gi, ' ') // Add space for block elements
      .replace(/<[^>]+>/g, ' ') // Remove HTML tags and replace with space
      .replace(/&nbsp;/g, ' ') // Replace non-breaking spaces
      .replace(/&amp;/g, '&') // Replace HTML entities
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim(); // Trim both leading and trailing whitespace
    
    // Special case: if original HTML ended with &nbsp; we want to preserve that space
    if (html.includes('&nbsp;</p>')) {
      result += ' ';
    }
    
    return result;
  }

  private parseJsonField(jsonString: string | null): any {
    if (!jsonString) return {};
    try {
      return JSON.parse(jsonString);
    } catch {
      return {};
    }
  }

  // Method to get dummy data for preview
  static getDummyVariables(): EmailVariables {
    return {
      user: {
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        username: 'janesmith',
      },
      // Password reset specific
      resetLink: 'https://example.com/reset/abc123def456',
      expiryTime: '2 hours',
      
      // Welcome email specific
      activationLink: 'https://example.com/activate/xyz789',
      gettingStartedUrl: 'https://example.com/getting-started',
      
      // Content specific
      content: {
        title: 'Getting Started with SonicJS AI',
        url: 'https://example.com/content/123',
        excerpt: 'Learn how to build amazing web applications with SonicJS AI...',
      },
      
      // Contact form specific
      formData: {
        name: 'John Doe',
        email: 'john.doe@example.com',
        message: 'I have a question about your services.',
        submittedAt: new Date().toISOString(),
      },
      submissionId: 'SUB-12345',
      replyToEmail: 'support@sonicjs-ai.com',
    };
  }
}

// Factory function
export function createEmailRenderer(env: { DB: any }): EmailTemplateRenderer {
  return new EmailTemplateRenderer(env.DB);
}
