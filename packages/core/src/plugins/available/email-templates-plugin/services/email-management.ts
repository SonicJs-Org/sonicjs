import { 
  EmailTheme, 
  EmailTemplate, 
  NewEmailTheme, 
  NewEmailTemplate,
  EmailVariable,
  NewEmailVariable
} from '../schema';
import { DEFAULT_EMAIL_THEME, SAMPLE_EMAIL_TEMPLATES } from '../data/default-email-theme';

export interface EmailManagementService {
  // Theme management
  createTheme(theme: Omit<NewEmailTheme, 'id' | 'createdAt' | 'updatedAt'>): Promise<string>;
  getThemes(): Promise<EmailTheme[]>;
  getThemeById(id: string): Promise<EmailTheme | null>;
  updateTheme(id: string, updates: Partial<EmailTheme>): Promise<void>;
  deleteTheme(id: string): Promise<void>;
  setDefaultTheme(id: string): Promise<void>;

  // Template management
  createTemplate(template: Omit<NewEmailTemplate, 'id' | 'createdAt' | 'updatedAt'>): Promise<string>;
  getTemplates(): Promise<EmailTemplate[]>;
  getTemplateById(id: string): Promise<EmailTemplate | null>;
  getTemplateBySlug(slug: string): Promise<EmailTemplate | null>;
  updateTemplate(id: string, updates: Partial<EmailTemplate>): Promise<void>;
  deleteTemplate(id: string): Promise<void>;

  // Variable management
  createVariable(variable: Omit<NewEmailVariable, 'id' | 'createdAt'>): Promise<string>;
  getVariables(): Promise<EmailVariable[]>;
  getSystemVariables(): Promise<EmailVariable[]>;
  
  // Setup and initialization
  initializeDefaultData(): Promise<void>;
}

export class DatabaseEmailManagementService implements EmailManagementService {
  constructor(private db: any, private defaultUserId: string) {}

  // Theme management
  async createTheme(theme: Omit<NewEmailTheme, 'id' | 'createdAt' | 'updatedAt'>): Promise<string> {
    const id = crypto.randomUUID();
    const now = new Date();

    const stmt = this.db.prepare(`
      INSERT INTO email_themes (
        id, name, description, html_template, css_styles, 
        variables, is_default, is_active, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      id,
      theme.name,
      theme.description || null,
      theme.htmlTemplate,
      theme.cssStyles,
      theme.variables || null,
      theme.isDefault ? 1 : 0,
      theme.isActive ? 1 : 0,
      theme.createdBy,
      Math.floor(now.getTime() / 1000),
      Math.floor(now.getTime() / 1000)
    ).run();

    // If this is set as default, unset other defaults
    if (theme.isDefault) {
      await this.setDefaultTheme(id);
    }

    return id;
  }

  async getThemes(): Promise<EmailTheme[]> {
    const stmt = this.db.prepare('SELECT * FROM email_themes ORDER BY is_default DESC, name ASC');
    const results = await stmt.all();
    return results.results.map(this.mapThemeFromDb);
  }

  async getThemeById(id: string): Promise<EmailTheme | null> {
    const stmt = this.db.prepare('SELECT * FROM email_themes WHERE id = ?');
    const result = await stmt.bind(id).first();
    return result ? this.mapThemeFromDb(result) : null;
  }

  async updateTheme(id: string, updates: Partial<EmailTheme>): Promise<void> {
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.name !== undefined) {
      fields.push('name = ?');
      values.push(updates.name);
    }
    if (updates.description !== undefined) {
      fields.push('description = ?');
      values.push(updates.description);
    }
    if (updates.htmlTemplate !== undefined) {
      fields.push('html_template = ?');
      values.push(updates.htmlTemplate);
    }
    if (updates.cssStyles !== undefined) {
      fields.push('css_styles = ?');
      values.push(updates.cssStyles);
    }
    if (updates.variables !== undefined) {
      fields.push('variables = ?');
      values.push(updates.variables);
    }
    if (updates.isActive !== undefined) {
      fields.push('is_active = ?');
      values.push(updates.isActive ? 1 : 0);
    }

    if (fields.length === 0) return;

    fields.push('updated_at = ?');
    values.push(Math.floor(Date.now() / 1000));
    values.push(id);

    const stmt = this.db.prepare(`
      UPDATE email_themes 
      SET ${fields.join(', ')} 
      WHERE id = ?
    `);

    await stmt.bind(...values).run();

    // Handle default theme change
    if (updates.isDefault) {
      await this.setDefaultTheme(id);
    }
  }

  async deleteTheme(id: string): Promise<void> {
    // Check if theme is in use by templates
    const templatesStmt = this.db.prepare('SELECT COUNT(*) as count FROM email_templates WHERE theme_id = ?');
    const templateCount = await templatesStmt.bind(id).first();
    
    if (templateCount.count > 0) {
      throw new Error('Cannot delete theme that is in use by email templates');
    }

    const stmt = this.db.prepare('DELETE FROM email_themes WHERE id = ?');
    await stmt.bind(id).run();
  }

  async setDefaultTheme(id: string): Promise<void> {
    // First, unset all other defaults
    const unsetStmt = this.db.prepare('UPDATE email_themes SET is_default = 0');
    await unsetStmt.run();

    // Then set the specified theme as default
    const setStmt = this.db.prepare('UPDATE email_themes SET is_default = 1 WHERE id = ?');
    await setStmt.bind(id).run();
  }

  // Template management
  async createTemplate(template: Omit<NewEmailTemplate, 'id' | 'createdAt' | 'updatedAt'>): Promise<string> {
    const id = crypto.randomUUID();
    const now = new Date();

    const stmt = this.db.prepare(`
      INSERT INTO email_templates (
        id, theme_id, name, slug, subject, markdown_content,
        variables, metadata, is_active, version, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      id,
      template.themeId,
      template.name,
      template.slug,
      template.subject,
      template.markdownContent,
      template.variables || null,
      template.metadata || null,
      template.isActive ? 1 : 0,
      template.version,
      template.createdBy,
      Math.floor(now.getTime() / 1000),
      Math.floor(now.getTime() / 1000)
    ).run();

    return id;
  }

  async getTemplates(): Promise<EmailTemplate[]> {
    const stmt = this.db.prepare(`
      SELECT t.*, th.name as theme_name 
      FROM email_templates t 
      LEFT JOIN email_themes th ON t.theme_id = th.id 
      ORDER BY t.name ASC
    `);
    const results = await stmt.all();
    return results.results.map(this.mapTemplateFromDb);
  }

  async getTemplateById(id: string): Promise<EmailTemplate | null> {
    const stmt = this.db.prepare('SELECT * FROM email_templates WHERE id = ?');
    const result = await stmt.bind(id).first();
    return result ? this.mapTemplateFromDb(result) : null;
  }

  async getTemplateBySlug(slug: string): Promise<EmailTemplate | null> {
    const stmt = this.db.prepare('SELECT * FROM email_templates WHERE slug = ? AND is_active = 1');
    const result = await stmt.bind(slug).first();
    return result ? this.mapTemplateFromDb(result) : null;
  }

  async updateTemplate(id: string, updates: Partial<EmailTemplate>): Promise<void> {
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.themeId !== undefined) {
      fields.push('theme_id = ?');
      values.push(updates.themeId);
    }
    if (updates.name !== undefined) {
      fields.push('name = ?');
      values.push(updates.name);
    }
    if (updates.slug !== undefined) {
      fields.push('slug = ?');
      values.push(updates.slug);
    }
    if (updates.subject !== undefined) {
      fields.push('subject = ?');
      values.push(updates.subject);
    }
    if (updates.markdownContent !== undefined) {
      fields.push('markdown_content = ?');
      values.push(updates.markdownContent);
    }
    if (updates.variables !== undefined) {
      fields.push('variables = ?');
      values.push(updates.variables);
    }
    if (updates.metadata !== undefined) {
      fields.push('metadata = ?');
      values.push(updates.metadata);
    }
    if (updates.isActive !== undefined) {
      fields.push('is_active = ?');
      values.push(updates.isActive ? 1 : 0);
    }
    if (updates.version !== undefined) {
      fields.push('version = ?');
      values.push(updates.version);
    }

    if (fields.length === 0) return;

    fields.push('updated_at = ?');
    values.push(Math.floor(Date.now() / 1000));
    values.push(id);

    const stmt = this.db.prepare(`
      UPDATE email_templates 
      SET ${fields.join(', ')} 
      WHERE id = ?
    `);

    await stmt.bind(...values).run();
  }

  async deleteTemplate(id: string): Promise<void> {
    const stmt = this.db.prepare('DELETE FROM email_templates WHERE id = ?');
    await stmt.bind(id).run();
  }

  // Variable management
  async createVariable(variable: Omit<NewEmailVariable, 'id' | 'createdAt'>): Promise<string> {
    const id = crypto.randomUUID();
    const now = new Date();

    const stmt = this.db.prepare(`
      INSERT INTO email_variables (
        id, name, display_name, description, data_type, 
        default_value, is_system, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      id,
      variable.name,
      variable.displayName,
      variable.description || null,
      variable.dataType,
      variable.defaultValue || null,
      variable.isSystem ? 1 : 0,
      Math.floor(now.getTime() / 1000)
    ).run();

    return id;
  }

  async getVariables(): Promise<EmailVariable[]> {
    const stmt = this.db.prepare('SELECT * FROM email_variables ORDER BY is_system DESC, name ASC');
    const results = await stmt.all();
    return results.results.map(this.mapVariableFromDb);
  }

  async getSystemVariables(): Promise<EmailVariable[]> {
    const stmt = this.db.prepare('SELECT * FROM email_variables WHERE is_system = 1 ORDER BY name ASC');
    const results = await stmt.all();
    return results.results.map(this.mapVariableFromDb);
  }

  // Setup and initialization
  async initializeDefaultData(): Promise<void> {
    // Check if default theme exists
    const existingTheme = await this.db.prepare('SELECT id FROM email_themes WHERE name = ?')
      .bind(DEFAULT_EMAIL_THEME.name).first();

    let themeId: string;

    if (!existingTheme) {
      // Create default theme
      themeId = await this.createTheme({
        ...DEFAULT_EMAIL_THEME,
        createdBy: this.defaultUserId,
      });
    } else {
      themeId = existingTheme.id;
    }

    // Create sample templates if they don't exist
    for (const templateData of SAMPLE_EMAIL_TEMPLATES) {
      const existing = await this.db.prepare('SELECT id FROM email_templates WHERE slug = ?')
        .bind(templateData.slug).first();

      if (!existing) {
        await this.createTemplate({
          themeId,
          name: templateData.name,
          slug: templateData.slug,
          subject: templateData.subject,
          markdownContent: templateData.markdownContent,
          variables: templateData.variables,
          metadata: '{}',
          isActive: true,
          version: 1,
          createdBy: this.defaultUserId,
        });
      }
    }

    // Create system variables
    await this.createSystemVariables();
  }

  private async createSystemVariables(): Promise<void> {
    const systemVariables = [
      { name: 'user.firstName', displayName: 'User First Name', dataType: 'string', description: 'First name of the recipient' },
      { name: 'user.lastName', displayName: 'User Last Name', dataType: 'string', description: 'Last name of the recipient' },
      { name: 'user.email', displayName: 'User Email', dataType: 'string', description: 'Email address of the recipient' },
      { name: 'site.name', displayName: 'Site Name', dataType: 'string', description: 'Name of the website' },
      { name: 'site.url', displayName: 'Site URL', dataType: 'string', description: 'URL of the website' },
      { name: 'site.logo', displayName: 'Site Logo', dataType: 'string', description: 'Logo URL of the website' },
      { name: 'date.now', displayName: 'Current Date', dataType: 'date', description: 'Current date in YYYY-MM-DD format' },
      { name: 'date.year', displayName: 'Current Year', dataType: 'string', description: 'Current year' },
    ];

    for (const variable of systemVariables) {
      const existing = await this.db.prepare('SELECT id FROM email_variables WHERE name = ?')
        .bind(variable.name).first();

      if (!existing) {
        await this.createVariable({
          ...variable,
          isSystem: true,
        });
      }
    }
  }

  // Helper methods to map database results to TypeScript objects
  private mapThemeFromDb(dbResult: any): EmailTheme {
    return {
      id: dbResult.id,
      name: dbResult.name,
      description: dbResult.description,
      htmlTemplate: dbResult.html_template,
      cssStyles: dbResult.css_styles,
      variables: dbResult.variables,
      isDefault: Boolean(dbResult.is_default),
      isActive: Boolean(dbResult.is_active),
      createdBy: dbResult.created_by,
      createdAt: new Date(dbResult.created_at * 1000),
      updatedAt: new Date(dbResult.updated_at * 1000),
    };
  }

  private mapTemplateFromDb(dbResult: any): EmailTemplate {
    return {
      id: dbResult.id,
      themeId: dbResult.theme_id,
      name: dbResult.name,
      slug: dbResult.slug,
      subject: dbResult.subject,
      markdownContent: dbResult.markdown_content,
      variables: dbResult.variables,
      metadata: dbResult.metadata,
      isActive: Boolean(dbResult.is_active),
      version: dbResult.version,
      createdBy: dbResult.created_by,
      createdAt: new Date(dbResult.created_at * 1000),
      updatedAt: new Date(dbResult.updated_at * 1000),
    };
  }

  private mapVariableFromDb(dbResult: any): EmailVariable {
    return {
      id: dbResult.id,
      name: dbResult.name,
      displayName: dbResult.display_name,
      description: dbResult.description,
      dataType: dbResult.data_type,
      defaultValue: dbResult.default_value,
      isSystem: Boolean(dbResult.is_system),
      createdAt: new Date(dbResult.created_at * 1000),
    };
  }
}

// Factory function
export function createEmailManagementService(env: { DB: any }, defaultUserId: string): EmailManagementService {
  return new DatabaseEmailManagementService(env.DB, defaultUserId);
}