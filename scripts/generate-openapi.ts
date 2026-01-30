import fs from 'fs';
import path from 'path';

import { openapi } from '../src/openapi';

const outputPath = path.resolve(process.cwd(), 'openapi.json');
const json = JSON.stringify(openapi, null, 2);

fs.writeFileSync(outputPath, json, 'utf-8');
console.log(`OpenAPI spec written to ${outputPath}`);
