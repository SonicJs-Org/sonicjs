#!/usr/bin/env node

import fs from 'fs-extra'
import path from 'path'
import { fileURLToPath } from 'url'
import prompts from 'prompts'
import kleur from 'kleur'
import ora from 'ora'
import { execa } from 'execa'
import validatePackageName from 'validate-npm-package-name'
import { initTelemetry, track, shutdown, isEnabled } from './telemetry.js'
import { displayTelemetryNotice } from './telemetry-notice.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// Read version from package.json
const packageJsonPath = path.join(__dirname, '../package.json')
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'))
const VERSION = packageJson.version

// Templates available
const TEMPLATES = {
  starter: {
    name: 'Starter (Blog & Content)',
    description: 'Perfect for blogs, documentation, and content sites',
    color: 'blue'
  },
  // Future templates
  // ecommerce: {
  //   name: 'E-commerce',
  //   description: 'Online store with products and checkout',
  //   color: 'green'
  // },
}

// Banner
console.log()
console.log(kleur.bold().cyan('✨ Create SonicJS App'))
console.log(kleur.dim(`   v${VERSION}`))
console.log()

// Parse arguments
const args = process.argv.slice(2)
const projectName = args[0]
const flags = {
  skipInstall: args.includes('--skip-install'),
  skipGit: args.includes('--skip-git'),
  skipCloudflare: args.includes('--skip-cloudflare'),
  template: args.find(arg => arg.startsWith('--template='))?.split('=')[1],
  databaseName: args.find(arg => arg.startsWith('--database='))?.split('=')[1],
  bucketName: args.find(arg => arg.startsWith('--bucket='))?.split('=')[1],
  skipExample: args.includes('--skip-example'),
  includeExample: args.includes('--include-example')
}

async function main() {
  const startTime = Date.now()

  try {
    // Initialize telemetry
    await initTelemetry()

    // Show telemetry notice if enabled
    if (isEnabled()) {
      displayTelemetryNotice()
    }

    // Track installation started
    await track('installation_started', {
      template: flags.template || 'starter',
      skipInstall: flags.skipInstall || false,
      skipGit: flags.skipGit || false,
      skipCloudflare: flags.skipCloudflare || false
    })

    // Get project details
    const answers = await getProjectDetails(projectName)

    // Create project
    await createProject(answers, flags)

    // Track installation completed
    const duration = Date.now() - startTime
    await track('installation_completed', {
      duration,
      template: answers.template,
      createResources: answers.createResources || false,
      initGit: answers.initGit || false,
      skipInstall: answers.skipInstall || false,
      includeExample: answers.includeExample || false
    })

    // Success message
    printSuccessMessage(answers)

    // Shutdown telemetry (flush events)
    await shutdown()

  } catch (error) {
    if (error.message === 'cancelled') {
      // Track cancellation
      await track('installation_cancelled')
      await shutdown()

      console.log()
      console.log(kleur.yellow('⚠ Cancelled'))
      process.exit(0)
    }

    // Track failure
    const duration = Date.now() - startTime
    await track('installation_failed', {
      duration,
      errorType: error.message.split(':')[0].trim()
    })
    await shutdown()

    console.error()
    console.error(kleur.red('✖ Error:'), error.message)
    console.error()
    process.exit(1)
  }
}

async function getProjectDetails(initialName) {
  const questions = []

  // Project name
  if (!initialName) {
    questions.push({
      type: 'text',
      name: 'projectName',
      message: 'Project name:',
      initial: 'my-sonicjs-app',
      validate: (value) => {
        if (!value) return 'Project name is required'
        const validation = validatePackageName(value)
        if (!validation.validForNewPackages) {
          return validation.errors?.[0] || 'Invalid package name'
        }
        if (fs.existsSync(value)) {
          return `Directory "${value}" already exists`
        }
        return true
      }
    })
  }

  // Template selection - always use 'starter' since it's the only template
  // No need to ask user, just default to starter

  // Database name
  if (!flags.databaseName) {
    questions.push({
      type: 'text',
      name: 'databaseName',
      message: 'Database name:',
      initial: (prev, values) => `${values.projectName || initialName}-db`,
      validate: (value) => value ? true : 'Database name is required'
    })
  }

  // R2 bucket name
  if (!flags.bucketName) {
    questions.push({
      type: 'text',
      name: 'bucketName',
      message: 'R2 bucket name:',
      initial: (prev, values) => `${values.projectName || initialName}-media`,
      validate: (value) => value ? true : 'Bucket name is required'
    })
  }

  // Seed admin user
  questions.push({
    type: 'confirm',
    name: 'seedAdmin',
    message: 'Create admin user?',
    initial: true
  })

  // Admin email (only if seeding)
  questions.push({
    type: (prev, values) => values.seedAdmin ? 'text' : null,
    name: 'adminEmail',
    message: 'Admin email:',
    validate: (value) => {
      if (!value) return 'Admin email is required'
      // Basic email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailRegex.test(value)) return 'Please enter a valid email address'
      return true
    }
  })

  // Admin password (only if seeding)
  questions.push({
    type: (prev, values) => values.seedAdmin ? 'password' : null,
    name: 'adminPassword',
    message: 'Admin password:',
    validate: (value) => {
      if (!value) return 'Admin password is required'
      if (value.length < 8) return 'Password must be at least 8 characters'
      return true
    }
  })

  // Include example collection (only ask if neither flag is set)
  if (!flags.skipExample && !flags.includeExample) {
    questions.push({
      type: 'confirm',
      name: 'includeExample',
      message: 'Include example blog collection?',
      initial: true
    })
  }

  // Create Cloudflare resources
  if (!flags.skipCloudflare) {
    questions.push({
      type: 'confirm',
      name: 'createResources',
      message: 'Create Cloudflare resources now? (requires wrangler)',
      initial: true
    })
  }

  // Initialize git
  if (!flags.skipGit) {
    questions.push({
      type: 'confirm',
      name: 'initGit',
      message: 'Initialize git repository?',
      initial: true
    })
  }

  const answers = await prompts(questions, {
    onCancel: () => {
      throw new Error('cancelled')
    }
  })

  return {
    projectName: initialName || answers.projectName,
    template: flags.template || 'starter', // Always default to starter template
    databaseName: flags.databaseName || answers.databaseName || `${initialName || answers.projectName}-db`,
    bucketName: flags.bucketName || answers.bucketName || `${initialName || answers.projectName}-media`,
    seedAdmin: answers.seedAdmin !== undefined ? answers.seedAdmin : true,
    adminEmail: answers.adminEmail,
    adminPassword: answers.adminPassword,
    includeExample: flags.skipExample ? false : (flags.includeExample ? true : (answers.includeExample !== undefined ? answers.includeExample : true)),
    createResources: flags.skipCloudflare ? false : answers.createResources,
    runMigrations: true, // Always run migrations automatically
    initGit: flags.skipGit ? false : answers.initGit,
    skipInstall: flags.skipInstall
  }
}

async function createProject(answers, flags) {
  const {
    projectName,
    template,
    databaseName,
    bucketName,
    adminEmail,
    adminPassword,
    includeExample,
    createResources,
    runMigrations,
    seedAdmin,
    initGit,
    skipInstall
  } = answers

  const targetDir = path.resolve(process.cwd(), projectName)

  console.log()
  const spinner = ora('Creating project...').start()

  try {
    // 1. Copy template
    spinner.text = 'Copying template files...'
    await copyTemplate(template, targetDir, {
      projectName,
      databaseName,
      bucketName,
      seedAdmin,
      adminEmail,
      adminPassword,
      includeExample
    })
    spinner.succeed('Copied template files')

    // 2. Create Cloudflare resources
    let databaseId = 'YOUR_DATABASE_ID'
    let resourcesCreated = false
    if (createResources) {
      spinner.start('Creating Cloudflare resources...')
      try {
        const result = await createCloudflareResources(databaseName, bucketName, targetDir)
        databaseId = result.databaseId || 'YOUR_DATABASE_ID'
        resourcesCreated = result.success
        if (resourcesCreated) {
          spinner.succeed('Created Cloudflare resources')
        } else {
          spinner.warn('Cloudflare resources partially created - see details above')
        }
      } catch (error) {
        spinner.warn('Failed to create Cloudflare resources')
        console.log(kleur.dim('  You can create them manually later'))
      }
    }

    // Store resources status for success message
    answers.resourcesCreated = resourcesCreated
    answers.databaseIdSet = databaseId !== 'YOUR_DATABASE_ID'

    // 3. Update wrangler.toml with database ID
    spinner.start('Updating configuration...')
    await updateWranglerConfig(targetDir, { databaseName, databaseId, bucketName })
    spinner.succeed('Updated configuration')

    // 4. Install dependencies
    if (!skipInstall) {
      spinner.start('Installing dependencies...')
      await installDependencies(targetDir)
      spinner.succeed('Installed dependencies')

      // Copy migrations after install
      spinner.start('Copying database migrations...')
      await copyMigrationsFromCore(targetDir)
      spinner.succeed('Copied database migrations')
    }

    // 5. Initialize git
    if (initGit) {
      spinner.start('Initializing git repository...')
      await initializeGit(targetDir)
      spinner.succeed('Initialized git repository')
    }

    // 6. Run migrations (always run locally, even if remote resources weren't created)
    if (runMigrations && !skipInstall) {
      spinner.start('Running database migrations...')
      try {
        await runDatabaseMigrations(targetDir)
        spinner.succeed('Database migrations completed')
        answers.migrationsRan = true
      } catch (error) {
        spinner.warn('Failed to run migrations')
        console.log(kleur.dim(`  ${error.message}`))
        console.log(kleur.dim('  You can run them manually with: npm run db:migrate:local'))
        answers.migrationsRan = false
      }
    } else if (runMigrations && skipInstall) {
      spinner.info('Skipping migrations - run after npm install')
      answers.migrationsRan = false
    }

    // 7. Seed admin user
    if (seedAdmin && !skipInstall && answers.migrationsRan) {
      spinner.start('Seeding admin user...')
      try {
        await seedAdminUser(targetDir)
        spinner.succeed('Admin user created')
        answers.adminSeeded = true
      } catch (error) {
        spinner.warn('Failed to seed admin user')
        console.log(kleur.dim(`  ${error.message}`))
        console.log(kleur.dim('  You can run it manually with: npm run seed'))
        answers.adminSeeded = false
      }
    } else if (seedAdmin && !answers.migrationsRan) {
      spinner.info('Skipping seed - migrations not completed')
      answers.adminSeeded = false
    }

    spinner.succeed(kleur.bold().green('✓ Project created successfully!'))

  } catch (error) {
    spinner.fail('Failed to create project')
    throw error
  }
}

async function copyTemplate(templateName, targetDir, options) {
  // Templates are in the package: node_modules/create-sonicjs/templates/starter
  // __dirname points to src/, so we go up one level to get to templates/
  const templateDir = path.resolve(__dirname, '..', 'templates', templateName)

  // Check if template exists
  if (!fs.existsSync(templateDir)) {
    throw new Error(`Template "${templateName}" not found at path: ${templateDir}`)
  }

  // Copy template
  await fs.copy(templateDir, targetDir, {
    filter: (src) => {
      // Skip node_modules, .git, dist, etc.
      const name = path.basename(src)
      if (['.git', 'node_modules', 'dist', '.wrangler', '.mf'].includes(name)) {
        return false
      }
      return true
    }
  })

  // Update package.json
  const packageJsonPath = path.join(targetDir, 'package.json')
  const packageJson = await fs.readJson(packageJsonPath)
  packageJson.name = options.projectName
  packageJson.version = '0.1.0'
  packageJson.private = true

  // Add @sonicjs-cms/core dependency
  packageJson.dependencies = {
    '@sonicjs-cms/core': '^2.8.0',
    ...packageJson.dependencies
  }

  await fs.writeJson(packageJsonPath, packageJson, { spaces: 2 })

  // Rename gitignore.template to .gitignore
  const gitignoreTemplatePath = path.join(targetDir, 'gitignore.template')
  const gitignorePath = path.join(targetDir, '.gitignore')
  if (fs.existsSync(gitignoreTemplatePath)) {
    await fs.rename(gitignoreTemplatePath, gitignorePath)
  }

  // Remove example collection if not wanted
  if (!options.includeExample) {
    const examplePath = path.join(targetDir, 'src/collections/blog-posts.collection.ts')
    if (fs.existsSync(examplePath)) {
      await fs.remove(examplePath)
    }
  }

  // Create admin seed script with provided credentials (only if creating admin user)
  if (options.seedAdmin && options.adminEmail && options.adminPassword) {
    await createAdminSeedScript(targetDir, {
      email: options.adminEmail,
      password: options.adminPassword
    })
  }
}

async function createAdminSeedScript(targetDir, { email, password }) {
  const seedScriptContent = `import { createDb, users } from '@sonicjs-cms/core'
import { eq } from 'drizzle-orm'
import * as crypto from 'crypto'
import { getPlatformProxy } from 'wrangler'

/**
 * Seed script to create initial admin user
 *
 * Run this script after migrations:
 * npm run db:migrate:local
 * npm run seed
 *
 * Admin credentials:
 * Email: ${email}
 * Password: [as entered during setup]
 */

async function seed() {
  // Get D1 database from Cloudflare environment using wrangler's getPlatformProxy
  const { env, dispose } = await getPlatformProxy()

  if (!env?.DB) {
    console.error('❌ Error: DB binding not found')
    console.error('')
    console.error('Make sure you have:')
    console.error('1. Created your D1 database: wrangler d1 create <database-name>')
    console.error('2. Updated wrangler.toml with the database_id')
    console.error('3. Run migrations: npm run db:migrate:local')
    console.error('')
    process.exit(1)
  }

  const db = createDb(env.DB)

  try {
    // Check if admin user already exists
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, '${email}'))
      .get()

    if (existingUser) {
      console.log('✓ Admin user already exists')
      console.log(\`  Email: ${email}\`)
      console.log(\`  Role: \${existingUser.role}\`)
      return
    }

    // Hash password using SHA-256 (same as SonicJS auth system)
    const data = '${password}' + 'salt-change-in-production'
    const passwordHash = crypto.createHash('sha256').update(data).digest('hex')
    const now = Date.now()
    const odid = \`admin-\${now}-\${Math.random().toString(36).substr(2, 9)}\`

    // Create admin user
    await db
      .insert(users)
      .values({
        id: odid,
        email: '${email}',
        username: '${email.split('@')[0]}',
        firstName: 'Admin',
        lastName: 'User',
        passwordHash: passwordHash,
        role: 'admin',
        isActive: true,
        createdAt: now,
        updatedAt: now
      })
      .run()

    console.log('✓ Admin user created successfully')
    console.log(\`  Email: ${email}\`)
    console.log(\`  Role: admin\`)
    console.log('')
    console.log('You can now login at: http://localhost:8787/auth/login')
  } catch (error) {
    console.error('❌ Error creating admin user:', error)
    await dispose()
    process.exit(1)
  }

  // Clean up the platform proxy
  await dispose()
}

// Run seed
seed()
  .then(() => {
    console.log('')
    console.log('✓ Seeding complete')
    process.exit(0)
  })
  .catch((error) => {
    console.error('❌ Seeding failed:', error)
    process.exit(1)
  })
`

  // Create scripts directory
  const scriptsDir = path.join(targetDir, 'scripts')
  await fs.ensureDir(scriptsDir)

  // Write seed script
  const seedScriptPath = path.join(scriptsDir, 'seed-admin.ts')
  await fs.writeFile(seedScriptPath, seedScriptContent)

  // Add seed script to package.json
  const packageJsonPath = path.join(targetDir, 'package.json')
  const packageJson = await fs.readJson(packageJsonPath)

  if (!packageJson.scripts) {
    packageJson.scripts = {}
  }

  packageJson.scripts.seed = 'tsx scripts/seed-admin.ts'

  await fs.writeJson(packageJsonPath, packageJson, { spaces: 2 })
}

async function copyMigrationsFromCore(targetDir) {
  // The migrations are in @sonicjs-cms/core/migrations
  // After npm install, they'll be in node_modules/@sonicjs-cms/core/migrations
  const coreMigrationsPath = path.join(targetDir, 'node_modules', '@sonicjs-cms', 'core', 'migrations')
  const projectMigrationsPath = path.join(targetDir, 'migrations')

  // Check if core migrations exist (they should after npm install)
  if (fs.existsSync(coreMigrationsPath)) {
    // Copy migrations to project directory
    await fs.copy(coreMigrationsPath, projectMigrationsPath)
  } else {
    // If migrations don't exist yet (npm install hasn't run), create a note file
    await fs.ensureDir(projectMigrationsPath)
    const noteContent = `# Migrations

Migrations will be copied from @sonicjs-cms/core after running npm install.

To manually copy migrations:
1. Install dependencies: npm install
2. Copy from: node_modules/@sonicjs-cms/core/migrations/
3. Copy to: migrations/

Or they should be automatically available after installation.
`
    await fs.writeFile(path.join(projectMigrationsPath, 'README.md'), noteContent)
  }
}

async function createCloudflareResources(databaseName, bucketName, targetDir) {
  // Check if wrangler is installed
  try {
    await execa('wrangler', ['--version'], { cwd: targetDir })
  } catch {
    throw new Error('wrangler is not installed. Install with: npm install -g wrangler')
  }

  let databaseId
  let dbCreated = false
  let bucketCreated = false

  // Create D1 database
  try {
    const { stdout, stderr } = await execa('wrangler', ['d1', 'create', databaseName], {
      cwd: targetDir
    })

    // Parse database_id from output
    const match = stdout.match(/database_id\s*=\s*["']([^"']+)["']/)
    if (match) {
      databaseId = match[1]
      dbCreated = true
    } else {
      console.log('')
      console.log(kleur.yellow('⚠ Warning: Could not parse database_id from wrangler output'))
      console.log(kleur.dim('  You may need to manually update wrangler.toml'))
    }
  } catch (error) {
    console.log('')
    console.log(kleur.yellow('⚠ D1 database creation failed:'))
    console.log(kleur.dim(`  ${error.message}`))
    if (error.stderr) {
      console.log(kleur.dim(`  ${error.stderr}`))
    }
    console.log('')
    console.log(kleur.dim('  Create manually with:'))
    console.log(kleur.dim(`  wrangler d1 create ${databaseName}`))
  }

  // Create R2 bucket
  try {
    await execa('wrangler', ['r2', 'bucket', 'create', bucketName], {
      cwd: targetDir
    })
    bucketCreated = true
  } catch (error) {
    console.log('')
    console.log(kleur.yellow('⚠ R2 bucket creation failed:'))
    console.log(kleur.dim(`  ${error.message}`))
    if (error.stderr) {
      console.log(kleur.dim(`  ${error.stderr}`))
    }
    console.log('')
    console.log(kleur.dim('  Create manually with:'))
    console.log(kleur.dim(`  wrangler r2 bucket create ${bucketName}`))
  }

  return {
    databaseId,
    success: dbCreated && bucketCreated
  }
}

async function updateWranglerConfig(targetDir, { databaseName, databaseId, bucketName }) {
  const wranglerPath = path.join(targetDir, 'wrangler.toml')
  let content = await fs.readFile(wranglerPath, 'utf-8')

  // Update database_name
  content = content.replace(/database_name\s*=\s*"[^"]*"/, `database_name = "${databaseName}"`)

  // Update database_id
  content = content.replace(/database_id\s*=\s*"[^"]*"/, `database_id = "${databaseId}"`)

  // Update bucket_name
  content = content.replace(/bucket_name\s*=\s*"[^"]*"/, `bucket_name = "${bucketName}"`)

  await fs.writeFile(wranglerPath, content)
}

async function installDependencies(targetDir) {
  // Detect package manager
  const packageManager = await detectPackageManager()

  const installCmd = packageManager === 'yarn' ? 'yarn' :
                     packageManager === 'pnpm' ? 'pnpm install' :
                     'npm install'

  await execa(packageManager, packageManager === 'yarn' ? [] : ['install'], {
    cwd: targetDir,
    stdio: 'ignore'
  })
}

async function detectPackageManager() {
  // Check parent directories for lock files
  let dir = process.cwd()

  while (dir !== path.parse(dir).root) {
    if (fs.existsSync(path.join(dir, 'pnpm-lock.yaml'))) return 'pnpm'
    if (fs.existsSync(path.join(dir, 'yarn.lock'))) return 'yarn'
    if (fs.existsSync(path.join(dir, 'package-lock.json'))) return 'npm'
    dir = path.dirname(dir)
  }

  return 'npm'
}

async function initializeGit(targetDir) {
  try {
    await execa('git', ['init'], { cwd: targetDir })
    await execa('git', ['add', '.'], { cwd: targetDir })
    await execa('git', ['commit', '-m', 'Initial commit from create-sonicjs-app'], {
      cwd: targetDir
    })
  } catch (error) {
    // Git init is optional, don't fail
  }
}

async function runDatabaseMigrations(targetDir) {
  try {
    const { stdout, stderr } = await execa('npm', ['run', 'db:migrate:local'], {
      cwd: targetDir,
      reject: false // Don't reject on non-zero exit code - check manually
    })

    // Check if migrations were successful - look for actual errors, not warnings
    if (stderr && (stderr.toLowerCase().includes('error:') || stderr.toLowerCase().includes('failed'))) {
      // Filter out wrangler version warnings
      if (!stderr.includes('Migrations were successfully applied')) {
        throw new Error(stderr)
      }
    }

    return stdout
  } catch (error) {
    throw new Error(`Migration failed: ${error.message}`)
  }
}

async function seedAdminUser(targetDir) {
  try {
    const { stdout, stderr } = await execa('npm', ['run', 'seed'], {
      cwd: targetDir,
      reject: false // Don't reject on non-zero exit code - check manually
    })

    // Check if seeding was successful - look for actual errors, not warnings
    if (stderr && (stderr.toLowerCase().includes('error:') || stderr.toLowerCase().includes('failed'))) {
      // Filter out wrangler version warnings
      if (!stdout.includes('Admin user created') && !stdout.includes('Admin user already exists')) {
        throw new Error(stderr)
      }
    }

    return stdout
  } catch (error) {
    throw new Error(`Seeding failed: ${error.message}`)
  }
}

function printSuccessMessage(answers) {
  const { projectName, createResources, skipInstall, resourcesCreated, databaseIdSet, migrationsRan, adminSeeded, seedAdmin } = answers

  console.log()
  console.log(kleur.bold().green('🎉 Success!'))
  console.log()
  console.log(kleur.bold('Next steps:'))
  console.log()
  console.log(kleur.cyan(`  cd ${projectName}`))

  if (skipInstall) {
    console.log(kleur.cyan('  npm install'))
    console.log()
    console.log(kleur.yellow('⚠ Important: After npm install, copy migrations:'))
    console.log(kleur.dim('  cp -r node_modules/@sonicjs-cms/core/migrations ./'))
  }

  // Show resource creation steps if they weren't created or failed
  if (!createResources || !resourcesCreated) {
    console.log()
    console.log(kleur.bold('Create Cloudflare resources:'))
    if (!databaseIdSet) {
      console.log(kleur.cyan(`  wrangler d1 create ${answers.databaseName}`))
      console.log(kleur.dim('  # Copy database_id to wrangler.toml'))
    }
    console.log(kleur.cyan(`  wrangler r2 bucket create ${answers.bucketName}`))
  }

  // Only show migration/seed steps if they weren't completed (shouldn't normally happen)
  const needsMigrations = !migrationsRan
  const needsSeeding = seedAdmin && !adminSeeded

  if (needsMigrations || needsSeeding) {
    console.log()
    console.log(kleur.bold('Complete setup:'))
    if (needsMigrations) {
      console.log(kleur.cyan('  npm run db:migrate:local'))
    }
    if (needsSeeding) {
      console.log(kleur.cyan('  npm run seed'))
    }
  }

  console.log()
  if (migrationsRan && (!seedAdmin || adminSeeded)) {
    console.log(kleur.bold().green('✓ Database is ready! Start development:'))
  } else {
    console.log(kleur.bold('Start development:'))
  }
  console.log(kleur.cyan('  npm run dev'))

  if (seedAdmin && answers.adminEmail) {
    console.log()
    console.log(kleur.bold('Login credentials:'))
    console.log(kleur.cyan(`  Email: ${answers.adminEmail}`))
    console.log(kleur.dim(`  Password: [as entered]`))
  }

  if (migrationsRan && (!seedAdmin || adminSeeded)) {
    console.log()
    console.log(kleur.green('✓ Everything is set up! Just run npm run dev and login.'))
  }

  console.log()
  console.log(kleur.bold('Visit:'))
  console.log(kleur.cyan('  http://localhost:8787/admin'))

  console.log()
  console.log(kleur.dim('Need help? Visit https://sonicjs.com'))
  console.log()
}

// Run
main()
