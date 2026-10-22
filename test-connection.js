import dotenv from 'dotenv';
import mongoose from 'mongoose';
import fs from 'node:fs';
import path from 'node:path';

const envPath = path.resolve(process.cwd(), '.env');
const envContents = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
const duplicateCounts = new Map();
for (const line of envContents.split(/\r?\n/)) {
  const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
  if (match) duplicateCounts.set(match[1], (duplicateCounts.get(match[1]) ?? 0) + 1);
}
const mongoUriSetBeforeDotenv = Boolean(process.env.MONGO_URI);
dotenv.config();

const mongoUri = process.env.MONGO_URI;
const expectedAtlasHost = 'cluster0.rkhtnw9.mongodb.net';

if (!mongoUri) {
  console.error('MongoDB connection test failed: MONGO_URI is not set.');
  process.exit(1);
}

function getUriDiagnostics(uri) {
  try {
    const parsed = new URL(uri);
    const authorityMatch = uri.match(/^mongodb(?:\+srv)?:\/\/([^/?#]*)/i);
    const authority = authorityMatch?.[1] ?? '';
    const userInfo = authority.includes('@')
      ? authority.slice(0, authority.lastIndexOf('@'))
      : '';
    const rawPassword = userInfo.includes(':')
      ? userInfo.slice(userInfo.indexOf(':') + 1)
      : '';
    const encodedDatabasePath = parsed.pathname.replace(/^\//, '');
    const authSourceValues = [...parsed.searchParams.entries()]
      .filter(([key]) => key.toLowerCase() === 'authsource')
      .map(([, value]) => value);
    const effectiveAuthSource = authSourceValues.at(-1)
      ?? (encodedDatabasePath ? decodeURIComponent(encodedDatabasePath) : 'admin');
    const username = decodeURIComponent(parsed.username);
    const password = decodeURIComponent(parsed.password);

    return {
      validUrlSyntax: true,
      usernamePresent: Boolean(parsed.username),
      passwordPresent: Boolean(parsed.password),
      hostMatchesConfiguredAtlasCluster: parsed.hostname.toLowerCase() === expectedAtlasHost,
      uriContainsWhitespace: /\s/.test(uri),
      usernameHasEdgeWhitespace: /^\s|\s$/.test(username),
      passwordHasEdgeWhitespace: /^\s|\s$/.test(password),
      passwordHasLiteralAngleBrackets: /[<>]/.test(rawPassword),
      passwordHasUnescapedReservedCharacters: /[$:/?#\[\]@]/.test(rawPassword),
      databasePathPresent: parsed.pathname.length > 1,
      duplicateMongoUriDefinitions: duplicateCounts.get('MONGO_URI') > 1,
      mongoUriWasSetBeforeDotenv: mongoUriSetBeforeDotenv,
      envFileFoundInWorkingDirectory: Boolean(envContents),
      uriMatchesEnvFileValue: !mongoUriSetBeforeDotenv
        && dotenv.parse(envContents).MONGO_URI === uri,
      authSourceExplicitlySet: authSourceValues.length > 0,
      effectiveAuthSource,
    };
  } catch {
    return { validUrlSyntax: false };
  }
}

function getDriverErrors(rootError) {
  const queue = [rootError];
  const seen = new Set();
  const errors = [];

  while (queue.length > 0) {
    const error = queue.shift();
    if (!error || typeof error !== 'object' || seen.has(error)) continue;
    seen.add(error);

    errors.push({
      name: error.name,
      code: error.code,
      codeName: error.codeName,
    });

    if (error.cause) queue.push(error.cause);
    if (error.reason) {
      queue.push(error.reason);
      for (const server of error.reason.servers?.values?.() ?? []) {
        if (server.error) queue.push(server.error);
      }
    }
  }

  return errors;
}

const diagnostics = getUriDiagnostics(mongoUri);
console.log('MongoDB URI diagnostics (credentials and host are not displayed):');
console.log(JSON.stringify(diagnostics, null, 2));

try {
  await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 10000 });
  console.log('MongoDB connection test succeeded.');
} catch (error) {
  console.error('MongoDB connection test failed.');
  const driverErrors = getDriverErrors(error);

  if (driverErrors.some((item) => item.code === 8000 || item.codeName === 'AtlasError')) {
    console.error('Failure category: Atlas rejected database authentication.');
  } else if (error?.name === 'MongoParseError') {
    console.error('Failure category: MongoDB URI could not be parsed.');
  } else if (error?.name === 'MongooseServerSelectionError') {
    console.error('Failure category: server selection or network connection failed.');
  } else {
    console.error('Failure category: unexpected MongoDB driver error.');
  }

  console.error('MongoDB driver error details (names and codes only):');
  console.error(JSON.stringify(driverErrors, null, 2));
  process.exitCode = 1;
} finally {
  await mongoose.disconnect();
}
