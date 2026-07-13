#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const routerFile = path.join(repositoryRoot, 'packages/trpc/server/router.ts');
const inventoryFile = path.join(repositoryRoot, 'ops/deploy/edge/gateway/trpc-procedures.json');

const configPath = ts.findConfigFile(path.dirname(routerFile), ts.sys.fileExists, 'tsconfig.json');
if (!configPath) {
  throw new Error('Unable to locate tsconfig.json');
}

const config = ts.readConfigFile(configPath, ts.sys.readFile);
if (config.error) {
  throw new Error(ts.flattenDiagnosticMessageText(config.error.messageText, '\n'));
}

const parsedConfig = ts.parseJsonConfigFileContent(config.config, ts.sys, repositoryRoot);
const program = ts.createProgram({ rootNames: [routerFile], options: parsedConfig.options });
const checker = program.getTypeChecker();
const sourceFile = program.getSourceFile(routerFile);

if (!sourceFile) {
  throw new Error('Unable to load the TRPC application router');
}

const propertyName = (node) => {
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node)) {
    return node.text;
  }
  throw new Error(`Unsupported router property name: ${node.getText()}`);
};

const resolveDeclaration = (expression) => {
  if (!ts.isIdentifier(expression)) {
    return null;
  }
  let symbol = checker.getSymbolAtLocation(expression);
  if (!symbol) {
    return null;
  }
  if (symbol.flags & ts.SymbolFlags.Alias) {
    symbol = checker.getAliasedSymbol(symbol);
  }
  return symbol.valueDeclaration || symbol.declarations?.[0] || null;
};

const routerObject = (expression) => {
  let candidate = expression;
  const declaration = resolveDeclaration(candidate);

  if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) {
    candidate = declaration.initializer;
  }

  if (ts.isObjectLiteralExpression(candidate)) {
    return candidate;
  }

  if (!ts.isCallExpression(candidate) || candidate.arguments.length === 0) {
    return null;
  }

  const callee = candidate.expression.getText();
  if (callee !== 'router' && !callee.endsWith('.router')) {
    return null;
  }

  return ts.isObjectLiteralExpression(candidate.arguments[0]) ? candidate.arguments[0] : null;
};

const procedures = [];
const visiting = new Set();

const walkRouter = (expression, prefix) => {
  const object = routerObject(expression);
  if (!object) {
    throw new Error(`Expected a router at ${prefix || '<root>'}: ${expression.getText()}`);
  }

  const identity = `${object.getSourceFile().fileName}:${object.pos}`;
  if (visiting.has(identity)) {
    throw new Error(`Router cycle detected at ${prefix || '<root>'}`);
  }
  visiting.add(identity);

  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) {
      throw new Error(`Unsupported router member: ${property.getText()}`);
    }

    const name = propertyName(property.name);
    const nextPrefix = prefix ? `${prefix}.${name}` : name;
    const value = ts.isPropertyAssignment(property) ? property.initializer : property.name;

    if (routerObject(value)) {
      walkRouter(value, nextPrefix);
    } else {
      procedures.push(nextPrefix);
    }
  }

  visiting.delete(identity);
};

let appRouterDeclaration = null;
for (const statement of sourceFile.statements) {
  if (!ts.isVariableStatement(statement)) {
    continue;
  }
  for (const declaration of statement.declarationList.declarations) {
    if (ts.isIdentifier(declaration.name) && declaration.name.text === 'appRouter') {
      appRouterDeclaration = declaration;
    }
  }
}

if (!appRouterDeclaration?.initializer) {
  throw new Error('Unable to find appRouter initializer');
}

walkRouter(appRouterDeclaration.initializer, '');

const sortedProcedures = [...new Set(procedures)].sort();
if (sortedProcedures.length !== procedures.length) {
  throw new Error('Duplicate procedure names were generated');
}

const output = `${JSON.stringify(sortedProcedures, null, 2)}\n`;

if (process.argv.includes('--check')) {
  const current = fs.readFileSync(inventoryFile, 'utf8');
  if (current !== output) {
    process.stderr.write('TRPC edge inventory is stale. Regenerate it from the pinned router.\n');
    process.exitCode = 1;
  }
} else {
  process.stdout.write(output);
}
