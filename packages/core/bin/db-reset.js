#!/usr/bin/env node

import { execSync, spawn } from 'child_process';
import { readFileSync, writeFileSync, existsSync, rmSync } from 'fs';
import { createInterface } from 'readline';
import { join, dirname } from 'path';

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
};

function log(message, color = '') {
  console.log(`${color}${message}${colors.reset}`);
}

function execCommand(command, options = {}) {
  try {
    return execSync(command, { encoding: 'utf-8', stdio: options.silent ? 'pipe' : 'inherit', ...options });
  } catch (error) {
    if (options.ignoreError) return '';
    throw error;
  }
}

function execCommandOutput(command) {
  try {
    return execSync(command, { encoding: 'utf-8', stdio: 'pipe' }).trim();
  } catch {
    return '';
  }
}

async function prompt(question) {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.toLowerCase());
    });
  });
}

function findWranglerConfig() {
  // Prefer wrangler.toml, then wrangler.jsonc, then wrangler.json
  const candidates = ['wrangler.toml', 'wrangler.jsonc', 'wrangler.json'];
  let dir = process.cwd();
  for (let i = 0; i < 5; i++) {
    for (const filename of candidates) {
      const configPath = join(dir, filename);
      if (existsSync(configPath)) {
        return { path: configPath, dir, format: filename.endsWith('.toml') ? 'toml' : 'json' };
      }
    }
    dir = dirname(dir);
  }
  return null;
}

async function main() {
  log('\n🔧 SonicJS Database Reset Tool', colors.cyan + colors.bold);
  log('================================\n', colors.cyan);

  // Find wrangler config (toml, jsonc, or json)
  const wranglerInfo = findWranglerConfig();
  if (!wranglerInfo) {
    log('Error: Could not find wrangler.toml / wrangler.jsonc / wrangler.json in current or parent directories', colors.red);
    log('Please run this command from your SonicJS project directory.', colors.yellow);
    process.exit(1);
  }

  const { path: wranglerPath, dir: projectDir, format: wranglerFormat } = wranglerInfo;
  log(`Found wrangler config at: ${wranglerPath}`, colors.green);

  // Change to project directory
  process.chdir(projectDir);

  // Get the current branch name
  let branchName;
  try {
    branchName = execCommandOutput('git rev-parse --abbrev-ref HEAD');
  } catch {
    branchName = '';
  }

  if (!branchName || branchName === 'HEAD') {
    log('Error: Could not determine branch name', colors.red);
    process.exit(1);
  }

  // Create a safe database name from branch
  const safeBranch = branchName.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 50);
  const dbName = `sonicjs-worktree-${safeBranch}`;

  log(`Setting up fresh D1 database for worktree: ${branchName}`, colors.cyan);
  log(`Database name: ${dbName}\n`, colors.cyan);

  // Check if database already exists
  log('Checking for existing database...', colors.yellow);
  let existingDbId = '';
  try {
    const listOutput = execCommandOutput('npx wrangler d1 list --json 2>/dev/null');
    if (listOutput) {
      const databases = JSON.parse(listOutput);
      const existing = databases.find((db) => db.name === dbName);
      if (existing) {
        existingDbId = existing.uuid;
      }
    }
  } catch {
    // Ignore errors - database may not exist
  }

  let dbId = existingDbId;

  if (existingDbId) {
    log(`Database ${dbName} already exists with ID: ${existingDbId}`, colors.yellow);

    const answer = await prompt('Delete existing database and create fresh one? (y/N): ');
    if (answer === 'y' || answer === 'yes') {
      log('\nDeleting existing database...', colors.yellow);
      try {
        execCommand(`npx wrangler d1 delete "${dbName}" --skip-confirmation`, { silent: true });
        existingDbId = '';
        dbId = '';
      } catch (error) {
        log(`Warning: Failed to delete database: ${error.message}`, colors.yellow);
      }
    }
  }

  if (!existingDbId || !dbId) {
    // Create new database
    log(`\nCreating new D1 database: ${dbName}`, colors.cyan);
    let createOutput = '';
    try {
      createOutput = execCommandOutput(`npx wrangler d1 create "${dbName}" 2>&1`);
      console.log(createOutput);
    } catch (error) {
      log(`Error creating database: ${error.message}`, colors.red);
      process.exit(1);
    }

    // Extract database ID from creation output
    const idMatch = createOutput.match(/database_id\s*=\s*"([^"]+)"/);
    if (idMatch) {
      dbId = idMatch[1];
    }

    // If extraction failed, try listing databases
    if (!dbId) {
      try {
        const listOutput = execCommandOutput('npx wrangler d1 list --json');
        if (listOutput) {
          const databases = JSON.parse(listOutput);
          const created = databases.find((db) => db.name === dbName);
          if (created) {
            dbId = created.uuid;
          }
        }
      } catch {
        // Ignore
      }
    }
  }

  if (!dbId) {
    log('Error: Failed to get database ID', colors.red);
    process.exit(1);
  }

  log(`\nDatabase ID: ${dbId}`, colors.green);

  // Update wrangler config with the new database ID
  const configBasename = wranglerPath.split('/').pop();
  log(`\nUpdating ${configBasename}...`, colors.yellow);
  try {
    let wranglerContent = readFileSync(wranglerPath, 'utf-8');
    if (wranglerFormat === 'toml') {
      // TOML syntax: database_id = "value"
      wranglerContent = wranglerContent.replace(
        /database_id\s*=\s*"[^"]*"/,
        `database_id = "${dbId}"`
      );
      wranglerContent = wranglerContent.replace(
        /database_name\s*=\s*"[^"]*"/,
        `database_name = "${dbName}"`
      );
    } else {
      // JSON/JSONC syntax: "database_id": "value"
      wranglerContent = wranglerContent.replace(
        /"database_id"\s*:\s*"[^"]*"/,
        `"database_id": "${dbId}"`
      );
      wranglerContent = wranglerContent.replace(
        /"database_name"\s*:\s*"[^"]*"/,
        `"database_name": "${dbName}"`
      );
    }
    writeFileSync(wranglerPath, wranglerContent);
    log(`Updated ${configBasename} successfully`, colors.green);
  } catch (error) {
    log(`Error updating ${configBasename}: ${error.message}`, colors.red);
    process.exit(1);
  }

  // Reset local database by removing it
  log('\nResetting local database...', colors.yellow);
  const localDbPath = join(projectDir, '.wrangler', 'state', 'v3', 'd1');
  if (existsSync(localDbPath)) {
    try {
      rmSync(localDbPath, { recursive: true, force: true });
      log('Local database cleared.', colors.green);
    } catch (error) {
      log(`Warning: Could not clear local database: ${error.message}`, colors.yellow);
    }
  } else {
    log('No local database to clear.', colors.green);
  }

  // Run migrations on remote
  log('\nRunning migrations on remote database...', colors.cyan);
  try {
    execCommand(`npx wrangler d1 migrations apply "${dbName}" --remote`);
  } catch (error) {
    log(`Warning: Remote migrations may have failed: ${error.message}`, colors.yellow);
  }

  // Run migrations on local
  log('\nRunning migrations on local database...', colors.cyan);
  try {
    execCommand(`npx wrangler d1 migrations apply "${dbName}" --local`);
  } catch (error) {
    log(`Warning: Local migrations may have failed: ${error.message}`, colors.yellow);
  }

  log('\n==========================================', colors.green + colors.bold);
  log('Database setup complete!', colors.green + colors.bold);
  log(`Database name: ${dbName}`, colors.green);
  log(`Database ID: ${dbId}`, colors.green);
  log('Both remote and local databases are ready.', colors.green);
  log('==========================================\n', colors.green + colors.bold);
  log('You can now run: npm run dev', colors.cyan);
}

main().catch((error) => {
  log(`\nError: ${error.message}`, colors.red);
  process.exit(1);
});
